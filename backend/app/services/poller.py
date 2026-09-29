"""
Autonomous incident poller.

`ENABLE_AUTO_POLLING` and `POLL_INTERVAL_SECONDS` have existed in the configuration
and been reported by the settings API since the beginning, but nothing read them:
every triage had to be triggered by hand from the UI. This module implements the
loop those settings describe.

Behaviour:
  - Polls Sentinel on POLL_INTERVAL_SECONDS.
  - Triages incidents that are New/Active and have no stored report yet, so a
    restart never re-triages work already done (reports live in SQLite).
  - Optionally closes incidents the agent judges false positive, gated by
    AUTO_CLOSE_FALSE_POSITIVES and a confidence floor.
  - Processes a bounded number of incidents per cycle so a backlog cannot cause
    an unbounded burst of model spend.
"""

import asyncio
import logging
from typing import Optional, Set

from app import db
from app.config import settings
from app.agent.triage_agent import triage_agent
from app.services.sentinel_client import sentinel_client

logger = logging.getLogger("warden.poller")

# Ceiling on incidents triaged per cycle. A workspace that suddenly produces
# hundreds of incidents should not turn into hundreds of model calls in one pass.
MAX_PER_CYCLE = 5

# Only auto-close a false positive when the agent had enough evidence to say so.
AUTO_CLOSE_MIN_COMPLETENESS = 80

_task: Optional[asyncio.Task] = None
_seen_failures: Set[str] = set()


async def _triage_one(incident: dict) -> None:
    incident_id = incident.get("id")
    title = (incident.get("title") or "")[:70]
    logger.info(f"[auto] triaging {incident_id}: {title}")

    report = await triage_agent.triage_incident(incident)
    db.save_report(incident_id, report)

    verdict = report.get("verdict")
    completeness = report.get("evidence_completeness") or 0
    logger.info(f"[auto] {incident_id} -> {verdict} (evidence completeness {completeness}%)")

    db.record_audit(
        actor="auto-poller",
        action="auto_triage",
        status="SUCCESS",
        target=title,
        incident_id=incident_id,
        verified=True,
        detail=f"verdict={verdict}, evidence_completeness={completeness}",
    )

    if (
        settings.AUTO_CLOSE_FALSE_POSITIVES
        and verdict == "FALSE_POSITIVE"
        and completeness >= AUTO_CLOSE_MIN_COMPLETENESS
    ):
        reason = "Benign activity confirmed by automated triage"
        await sentinel_client.update_status(
            incident_id=incident_id,
            status="Closed",
            classification="FalsePositive",
            classification_reason=reason,
            labels=["Closed-FalsePositive", "AI-AutoClosed"],
        )
        db.record_audit(
            actor="auto-poller", action="auto_close", status="SUCCESS",
            target=title, incident_id=incident_id, verified=True, detail=reason,
        )
        logger.info(f"[auto] {incident_id} auto-closed as false positive")


async def _cycle() -> None:
    incidents = await sentinel_client.list_incidents()
    candidates = []
    for inc in incidents:
        incident_id = inc.get("id")
        if not incident_id or incident_id in _seen_failures:
            continue
        if (inc.get("status") or "").lower() not in ("new", "active"):
            continue
        if db.get_report(incident_id) is not None:
            continue  # already triaged, and that survived restarts
        candidates.append(inc)

    if not candidates:
        logger.debug("[auto] no untriaged incidents this cycle")
        return

    logger.info(f"[auto] {len(candidates)} untriaged incident(s); processing up to {MAX_PER_CYCLE}")
    for inc in candidates[:MAX_PER_CYCLE]:
        try:
            await _triage_one(inc)
        except Exception as e:
            incident_id = inc.get("id")
            logger.error(f"[auto] triage failed for {incident_id}: {e}")
            # Do not retry a poisonous incident every cycle forever.
            _seen_failures.add(incident_id)
            db.record_audit(
                actor="auto-poller", action="auto_triage", status="FAILED",
                target=(inc.get("title") or "")[:70], incident_id=incident_id,
                verified=False, detail=str(e)[:500],
            )


async def _loop() -> None:
    interval = max(30, int(settings.POLL_INTERVAL_SECONDS))
    logger.warning(
        f"Autonomous polling ENABLED: checking Sentinel every {interval}s, "
        f"max {MAX_PER_CYCLE} incidents per cycle, "
        f"auto-close false positives = {settings.AUTO_CLOSE_FALSE_POSITIVES}"
    )
    while True:
        try:
            await _cycle()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # A transient Sentinel or model error must not kill the loop.
            logger.error(f"[auto] poll cycle error: {e}")
        await asyncio.sleep(interval)


def start() -> None:
    """Start the poller if enabled. Safe to call more than once."""
    global _task
    if not settings.ENABLE_AUTO_POLLING:
        logger.info("Autonomous polling is disabled (ENABLE_AUTO_POLLING=False).")
        return
    if _task and not _task.done():
        return
    _task = asyncio.create_task(_loop(), name="sentinel-auto-poller")


async def stop() -> None:
    """Cancel the poller on shutdown so the process exits cleanly."""
    global _task
    if _task and not _task.done():
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
    _task = None


def status() -> dict:
    return {
        "enabled": settings.ENABLE_AUTO_POLLING,
        "running": bool(_task and not _task.done()),
        "interval_seconds": settings.POLL_INTERVAL_SECONDS,
        "max_per_cycle": MAX_PER_CYCLE,
        "auto_close_false_positives": settings.AUTO_CLOSE_FALSE_POSITIVES,
        "skipped_after_failure": len(_seen_failures),
    }
