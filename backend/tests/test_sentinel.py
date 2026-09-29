import pytest
from app.services.sentinel_client import sentinel_client
from app.services.threat_intel import threat_intel_service
from app.services.kql_runner import kql_runner

@pytest.mark.asyncio
async def test_list_incidents():
    incidents = await sentinel_client.list_incidents()
    assert len(incidents) > 0
    assert "title" in incidents[0]
    assert "severity" in incidents[0]

@pytest.mark.asyncio
async def test_threat_intel_private_ip():
    res = await threat_intel_service.lookup_ip_reputation("192.168.1.50")
    assert res["is_private"] is True
    assert res["verdict"] == "BENIGN_INTERNAL"

@pytest.mark.asyncio
async def test_threat_intel_malicious_ip():
    res = await threat_intel_service.lookup_ip_reputation("185.220.101.5")
    assert res["abuse_confidence_score"] > 70
    assert res["verdict"] == "MALICIOUS"

@pytest.mark.asyncio
async def test_kql_execution():
    query = "SigninLogs | take 5"
    res = await kql_runner.execute_kql(query)
    assert res["status"] == "SUCCESS"
    assert len(res["tables"]) > 0

@pytest.mark.asyncio
async def test_get_playbooks_offers_only_real_workflows_when_live():
    """
    The selector must not offer playbooks that do not exist.

    This previously merged a hardcoded catalogue of eight playbook names into the
    live result, so the UI listed containment options that could only fail when
    invoked. In live mode the list must come from deployed Logic Apps; in demo mode
    the sample catalogue is allowed but must be labelled as such.
    """
    playbooks = await sentinel_client.get_playbooks()
    assert isinstance(playbooks, list)
    for p in playbooks:
        assert p.get("name"), "every playbook needs a name to be invocable"

    if sentinel_client.is_live:
        # Nothing fabricated: sample entries must not leak into a live listing.
        categories = {p.get("category") for p in playbooks}
        assert "Sample (demo mode)" not in categories, \
            "demo catalogue leaked into the live playbook list"
    else:
        assert playbooks, "demo mode should still offer sample playbooks"
        assert all(p.get("category") == "Sample (demo mode)" for p in playbooks), \
            "demo playbooks must be labelled so they are not mistaken for deployed ones"

@pytest.mark.asyncio
async def test_trigger_playbook_reports_truthfully():
    """
    A playbook that was not actually invoked must NOT be reported as SUCCESS, and must
    not apply SOAR containment tags. Against a workspace with no such Logic App the
    correct outcome is FAILED (or NOT_PERMITTED), with tags withheld.
    """
    from app.services.remediation_service import remediation_service
    res = await remediation_service.execute_remediation(
        incident_id="inc-2026-9041",
        action_type="trigger_playbook",
        entity="Incident #9041",
        analyst_name="Test Analyst",
        parameters={"playbook_name": "SOAR-Revoke-User-Sessions-LogicApp", "notes": "Test containment"}
    )
    assert res["status"] in {"SUCCESS", "SIMULATED", "NOT_PERMITTED", "FAILED"}
    assert res["action_type"] == "trigger_playbook"
    assert res["result_message"]

    if res["status"] == "SUCCESS":
        assert "run_id" in res
        assert "Playbook:SOAR-Revoke-User-Sessions-LogicApp" in res["applied_tags"]
        assert "SOAR-Automated" in res["applied_tags"]
    else:
        # Nothing happened, so nothing may claim it did.
        assert res["applied_tags"] == []


@pytest.mark.asyncio
async def test_containment_never_claims_unverified_success():
    """Identity containment must not report SUCCESS unless the platform confirmed it."""
    from app.services.remediation_service import remediation_service
    for action, entity in [
        ("disable_account", "jdoe@cybersecurity.corp"),
        ("revoke_sessions", "jdoe@cybersecurity.corp"),
        ("isolate_endpoint", "WKS-EXEC-094"),
    ]:
        res = await remediation_service.execute_remediation(
            incident_id="inc-2026-9041",
            action_type=action,
            entity=entity,
            analyst_name="Test Analyst",
        )
        assert res["status"] in {"SUCCESS", "SIMULATED", "NOT_PERMITTED", "FAILED"}
        if res["status"] != "SUCCESS":
            assert res["applied_tags"] == [], f"{action} applied containment tags without succeeding"
