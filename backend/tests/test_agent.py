import pytest
from app.config import settings
from app.agent.triage_agent import triage_agent
from app.services.sentinel_client import sentinel_client

@pytest.fixture
def deterministic_agent():
    """
    Run the triage pipeline without calling a live model.

    This test previously invoked the real LLM and asserted on its output, which
    made it nondeterministic (it failed roughly one run in three), slow, and
    dependent on network access and model credits in CI. Disabling the client
    exercises the same orchestration - entity extraction, threat intel, KQL
    hunts, report assembly, progress events - through the deterministic reasoning
    path. Model-backed behaviour is measured properly by the evaluation harness in
    backend/evals, which is the right tool for a probabilistic component.
    """
    original = triage_agent.openai_client
    triage_agent.openai_client = None
    try:
        yield triage_agent
    finally:
        triage_agent.openai_client = original


@pytest.mark.asyncio
async def test_agent_triage_flow(deterministic_agent):
    incidents = await sentinel_client.list_incidents()
    target_inc = incidents[0]

    events_captured = []

    def progress_callback(event):
        events_captured.append(event)

    report = await deterministic_agent.triage_incident(target_inc, progress_callback=progress_callback)

    assert report is not None
    for field in ("verdict", "evidence_completeness", "evidence_gaps",
                  "mitre_attack", "model_used", "reasoning_tier"):
        assert field in report, f"report is missing '{field}'"

    assert report["verdict"] in {"TRUE_POSITIVE", "FALSE_POSITIVE", "SUSPICIOUS_ESCALATE", "BENIGN"}
    assert isinstance(report["evidence_gaps"], list)
    assert 0 <= report["evidence_completeness"] <= 100

    # Evidence completeness must stay consistent with the gap list it is derived from.
    if report["evidence_gaps"]:
        assert report["evidence_completeness"] <= 85, \
            "gaps were recorded but completeness was not capped"

    emitted = {e["event"] for e in events_captured}
    for expected in ("INVESTIGATION_STARTED", "MODEL_SELECTED", "VERDICT_GENERATED"):
        assert expected in emitted, f"progress stream never emitted {expected}"

def test_hybrid_model_selection():
    settings.LLM_ROUTING_MODE = "hybrid"

    # High severity -> configured reasoning tier
    high_inc = {"id": "inc-1", "severity": "High", "title": "Suspicious Activity", "tactics": ["Execution"]}
    res = triage_agent.select_triage_model(high_inc)
    assert res["model_name"] == settings.REASONING_MODEL_NAME
    assert res["reasoning_tier"] == "deep_reasoning"

    # Low severity routine -> configured fast tier
    low_inc = {"id": "inc-2", "severity": "Low", "title": "Routine Signin Anomaly", "tactics": ["InitialAccess"]}
    res = triage_agent.select_triage_model(low_inc)
    assert res["model_name"] == settings.FAST_MODEL_NAME
    assert res["reasoning_tier"] == "fast"

    # Incident #5153 specific verification
    inc_5153 = {
        "id": "53807bc4-c879-4b6e-8d8d-59b257d61fa4",
        "incidentNumber": 5153,
        "title": "Rare and potentially high-risk Office operations involving one user",
        "description": "Identifies Office operations that are typically rare and can provide capabilities useful to attackers.",
        "severity": "Low",
        "tactics": [],
        "alertsCount": 1
    }
    res_5153 = triage_agent.select_triage_model(inc_5153)
    assert res_5153["model_name"] == settings.FAST_MODEL_NAME
    assert res_5153["reasoning_tier"] == "fast"
    assert "Low Severity" in res_5153["reason"]

    # Complex attack keyword in Medium severity -> configured reasoning tier
    complex_inc = {"id": "inc-3", "severity": "Medium", "title": "Encoded PowerShell and Ransomware Payload Detected", "tactics": ["Execution"]}
    res = triage_agent.select_triage_model(complex_inc)
    assert res["model_name"] == settings.REASONING_MODEL_NAME
    assert res["reasoning_tier"] == "deep_reasoning"

    # Multi-stage tactics (tactics >= 2) -> configured reasoning tier
    multistage_inc = {"id": "inc-4", "severity": "Medium", "title": "Generic Alert", "tactics": ["InitialAccess", "Persistence", "PrivilegeEscalation"]}
    res = triage_agent.select_triage_model(multistage_inc)
    assert res["model_name"] == settings.REASONING_MODEL_NAME
    assert res["reasoning_tier"] == "deep_reasoning"

def test_override_routing_modes():
    # Always Mini override
    settings.LLM_ROUTING_MODE = "always_mini"
    high_inc = {"id": "inc-1", "severity": "High", "title": "Ransomware Multi-Stage", "tactics": ["Execution", "Exfiltration"]}
    res = triage_agent.select_triage_model(high_inc)
    assert res["model_name"] == settings.FAST_MODEL_NAME
    assert res["reasoning_tier"] == "fast"

    # Always Astra override
    settings.LLM_ROUTING_MODE = "always_astra"
    low_inc = {"id": "inc-2", "severity": "Low", "title": "Minor Anomaly", "tactics": []}
    res = triage_agent.select_triage_model(low_inc)
    assert res["model_name"] == settings.REASONING_MODEL_NAME
    assert res["reasoning_tier"] == "deep_reasoning"

    # Reset back to hybrid
    settings.LLM_ROUTING_MODE = "hybrid"
