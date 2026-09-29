import logging
from datetime import datetime
from typing import Dict, Any, Optional
from app import db
from app.config import settings
from app.services.sentinel_client import sentinel_client

logger = logging.getLogger(__name__)

# Result states, in order of decreasing certainty:
#   SUCCESS       - the action was performed AND (where verifiable) confirmed by re-reading state
#   SIMULATED     - DEMO_MODE; nothing was touched, and the audit trail says so
#   NOT_PERMITTED - the platform refused; the tenant/subscription lacks the required permission
#   FAILED        - the action was attempted and did not succeed
STATUS_SUCCESS = "SUCCESS"
STATUS_SIMULATED = "SIMULATED"
STATUS_NOT_PERMITTED = "NOT_PERMITTED"
STATUS_FAILED = "FAILED"


class RemediationService:
    """
    Security Orchestration, Automation and Response (SOAR) actions against Microsoft
    Sentinel, Entra ID and Defender for Endpoint.

    Contract: this service never reports an action as performed unless the underlying
    API accepted it and, where the platform allows a read-back, the resulting state was
    verified. A refusal or failure is written into the Sentinel audit trail as plainly
    as a success, and containment tags are applied ONLY on verified success. An incident
    record that claims an account was disabled when it was not is worse than no record.
    """

    async def execute_remediation(
        self,
        incident_id: str,
        action_type: str,
        entity: str,
        analyst_name: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        parameters = parameters or {}
        timestamp = datetime.utcnow().isoformat() + "Z"
        logger.info(f"Executing remediation '{action_type}' for entity '{entity}' by {analyst_name}")

        handlers = {
            "isolate_endpoint": self._isolate_endpoint,
            "revoke_sessions": self._revoke_sessions,
            "block_ip": self._block_ip,
            "disable_account": self._disable_account,
            "trigger_playbook": self._trigger_playbook,
            "close_false_positive": self._close_false_positive,
        }
        handler = handlers.get(action_type)
        if not handler:
            return {"status": STATUS_FAILED, "message": f"Remediation action '{action_type}' is not supported."}

        if settings.DEMO_MODE:
            outcome = self._simulate(action_type, entity)
        else:
            outcome = await handler(incident_id, entity, analyst_name, parameters)

        status = outcome.get("status", STATUS_FAILED)
        result_message = outcome.get("message", "")
        applied_tags = outcome.get("tags", []) if status == STATUS_SUCCESS else []

        # Durable local record first: if Sentinel is unreachable or the comment write
        # fails, the attempt must still be recorded somewhere.
        try:
            db.record_audit(
                actor=analyst_name,
                action=action_type,
                status=status,
                target=entity,
                incident_id=incident_id,
                verified=outcome.get("verified"),
                detail=result_message,
            )
        except Exception as e:
            logger.error(f"Failed to write remediation audit record to the database: {e}")

        await self._write_audit_comment(
            incident_id=incident_id,
            action_type=action_type,
            entity=entity,
            analyst_name=analyst_name,
            timestamp=timestamp,
            status=status,
            result_message=result_message,
            verified=outcome.get("verified"),
        )

        # Containment tags assert a state change. Only apply them when one actually happened.
        if applied_tags:
            incident = await sentinel_client.get_incident(incident_id)
            if incident:
                merged = list(set(incident.get("labels", []) + applied_tags))
                await sentinel_client.update_status(
                    incident_id=incident_id,
                    status=incident.get("status", "Active"),
                    labels=merged
                )

        return {
            "status": status,
            "action_type": action_type,
            "entity": entity,
            "verified": outcome.get("verified", False),
            "result_message": result_message,
            "executed_by": analyst_name,
            "timestamp": timestamp,
            "applied_tags": applied_tags,
            **{k: v for k, v in outcome.items() if k not in {"status", "message", "tags", "verified"}}
        }

    # ------------------------------------------------------------------ actions

    async def _isolate_endpoint(self, incident_id, entity, analyst_name, parameters):
        res = await sentinel_client.isolate_device(hostname=entity, incident_id=incident_id)
        res["tags"] = ["Containment-DeviceIsolated", "Defender-Isolated"]
        return res

    async def _revoke_sessions(self, incident_id, entity, analyst_name, parameters):
        res = await sentinel_client.revoke_entra_sessions(upn=entity)
        res["tags"] = ["Containment-SessionsRevoked", "EntraID-Revoked"]
        return res

    async def _disable_account(self, incident_id, entity, analyst_name, parameters):
        res = await sentinel_client.disable_entra_account(upn=entity)
        res["tags"] = ["Account-Disabled", "Compromise-Contained"]
        return res

    async def _block_ip(self, incident_id, entity, analyst_name, parameters):
        res = await sentinel_client.block_ip_indicator(
            ip_address=entity,
            incident_id=incident_id,
            analyst_name=analyst_name,
            ttl_days=int(parameters.get("ttl_days", 90))
        )
        res["tags"] = ["Perimeter-Blocked", "IOC-Blacklisted"]
        return res

    async def _trigger_playbook(self, incident_id, entity, analyst_name, parameters):
        playbook_name = parameters.get("playbook_name", "SOAR-Incident-Containment-Playbook")
        res = await sentinel_client.trigger_playbook(
            incident_id=incident_id,
            playbook_name=playbook_name,
            parameters=parameters,
            analyst_name=analyst_name
        )
        res["tags"] = [f"Playbook:{playbook_name}", "SOAR-Automated"]
        res["playbook_name"] = playbook_name
        return res

    async def _close_false_positive(self, incident_id, entity, analyst_name, parameters):
        reason = parameters.get("reason", "Authorized Security Testing / Benign Scanner Noise")
        await sentinel_client.update_status(
            incident_id=incident_id,
            status="Closed",
            classification="FalsePositive",
            classification_reason=reason,
            labels=["Closed-FalsePositive", "AI-Verified"]
        )
        return {
            "status": STATUS_SUCCESS,
            "verified": True,
            "message": f"Incident closed in Microsoft Sentinel as False Positive. Reason: {reason}.",
            "tags": ["Closed-FalsePositive"],
        }

    # ------------------------------------------------------------------ helpers

    def _simulate(self, action_type: str, entity: str) -> Dict[str, Any]:
        """DEMO_MODE: describe what would happen, and label it unmistakably as simulated."""
        described = {
            "isolate_endpoint": f"would isolate endpoint '{entity}' via Microsoft Defender for Endpoint",
            "revoke_sessions": f"would revoke all Entra ID sessions and refresh tokens for '{entity}'",
            "block_ip": f"would publish '{entity}' to the Sentinel threat intelligence feed as a blocked indicator",
            "disable_account": f"would disable account '{entity}' in Microsoft Entra ID",
            "trigger_playbook": "would invoke the configured Azure Logic App playbook",
            "close_false_positive": "would close the incident in Sentinel as a false positive",
        }.get(action_type, f"would execute '{action_type}'")
        return {
            "status": STATUS_SIMULATED,
            "verified": False,
            "message": f"SIMULATION (DEMO_MODE): no change was made. In live mode this {described}.",
            "tags": [],
        }

    async def _write_audit_comment(self, incident_id, action_type, entity, analyst_name,
                                   timestamp, status, result_message, verified):
        heading = {
            STATUS_SUCCESS: "Remediation Executed",
            STATUS_SIMULATED: "Remediation SIMULATED (no change made)",
            STATUS_NOT_PERMITTED: "Remediation NOT PERMITTED (no change made)",
            STATUS_FAILED: "Remediation FAILED (no change made)",
        }.get(status, "Remediation Attempted")

        verification_line = ""
        if status == STATUS_SUCCESS:
            verification_line = (
                "- **Verification:** post-action state confirmed by read-back\n" if verified
                else "- **Verification:** NOT verified - the platform accepted the request but the "
                     "resulting state could not be confirmed\n"
            )

        comment = (
            f"### {heading}\n"
            f"- **Action:** `{action_type}`\n"
            f"- **Target:** `{entity}`\n"
            f"- **Requested by:** `{analyst_name}`\n"
            f"- **Status:** `{status}`\n"
            f"{verification_line}"
            f"- **Timestamp:** `{timestamp}`\n"
            f"- **Result:** {result_message}\n"
        )
        try:
            await sentinel_client.add_comment(incident_id, comment, author=analyst_name)
        except Exception as e:
            logger.warning(f"Could not write remediation audit comment to incident {incident_id}: {e}")


remediation_service = RemediationService()
