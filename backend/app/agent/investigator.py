"""
Adaptive investigation loop.

The fixed pipeline runs a set of hunts derived from the incident's entities and
then asks the model to summarise the results. The queries are chosen by code, so
the investigation is identical in shape for every incident: it cannot follow a
lead. If a hunt surfaces a second account touching a suspicious IP, nothing
queries that account.

This module gives the model the query tool directly. It sees the incident and the
enrichment already gathered, writes its own KQL, reads the rows that come back,
and decides what to ask next, until it has enough to conclude or it exhausts a
step budget.

Three bounds make that safe to run against a live workspace and a metered model:

  - every query passes through kql_guard (read-only, row-capped, single statement)
  - a hard ceiling on steps and on total queries
  - a token ceiling, after which the model is asked to conclude with what it has

The loop returns the same report shape as the fixed pipeline, so callers and the
evaluation harness are unaffected by which path produced it.
"""

import json
import logging
from typing import Any, Callable, Dict, List, Optional

from app.agent.kql_guard import validate_kql
from app.agent.prompts import SOC_TRIAGE_SYSTEM_PROMPT
from app.services.kql_runner import kql_runner
from app.services.threat_intel import threat_intel_service

logger = logging.getLogger(__name__)

MAX_STEPS = 6
MAX_QUERIES = 8
MAX_TOKENS_TOTAL = 60_000

INVESTIGATOR_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_kql_query",
            "description": (
                "Run a read-only KQL query against this Microsoft Sentinel workspace. "
                "Use it to test a specific hypothesis about the incident: corroborate a claim, "
                "establish a baseline for an entity, or follow a lead surfaced by an earlier "
                "result. Results are row-capped. If a table returns zero rows, that means no "
                "telemetry is available - it does NOT mean the activity did not happen."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "A single read-only KQL statement."},
                    "timespan_hours": {"type": "integer", "description": "Look-back window in hours (default 24, max 168)."},
                    "hypothesis": {
                        "type": "string",
                        "description": "What this query is meant to establish, in one sentence. Recorded in the investigation trail.",
                    },
                },
                "required": ["query", "hypothesis"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_ip_reputation",
            "description": "Look up an IP address against AbuseIPDB and threat intelligence feeds.",
            "parameters": {
                "type": "object",
                "properties": {"ip_address": {"type": "string"}},
                "required": ["ip_address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_available_tables",
            "description": (
                "List the tables that actually contain data in this workspace, with row counts. "
                "Call this first if unsure what telemetry exists - querying a table that was never "
                "populated wastes a step and proves nothing."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
    },
]

INVESTIGATOR_SYSTEM_PROMPT = (
    SOC_TRIAGE_SYSTEM_PROMPT
    + """

### Investigation Method (this session):
You have direct query access to the workspace. Investigate before concluding.

- Work from hypotheses. Each query should test something specific: does this account
  normally operate from this address, did anything else touch this indicator, is there
  a parent process. State the hypothesis when you call the tool.
- Follow what you find. A result that names a second account, host or address is a
  lead; query it rather than stopping at the first answer.
- Check what telemetry exists before assuming it is missing. `list_available_tables`
  tells you which tables hold data; a table with no rows proves nothing either way.
- You have a limited number of queries. Spend them on what would change your verdict,
  not on confirming what the incident already states.
- Stop when further queries would not change the conclusion, and return the final
  JSON report. Do not keep querying to appear thorough.

Everything you could not establish belongs in `evidence_gaps`, and
`evidence_completeness` must reflect it.
"""
)


async def _list_tables() -> Dict[str, Any]:
    """Which tables actually hold data, so the model does not query empty ones."""
    query = (
        "union withsource=TableName * "
        "| summarize Rows=count() by TableName "
        "| where Rows > 0 "
        "| top 25 by Rows desc"
    )
    res = await kql_runner.execute_kql(query, 168)
    tables = []
    for t in res.get("tables", []):
        for row in t.get("rows", []):
            tables.append(row)
    return {"tables_with_data": tables, "count": len(tables)}


async def _dispatch(name: str, args: Dict[str, Any], trail: List[Dict[str, Any]]) -> Dict[str, Any]:
    if name == "run_kql_query":
        raw_query = args.get("query", "")
        guard = validate_kql(raw_query, args.get("timespan_hours", 24))
        if not guard.ok:
            logger.warning(f"[investigator] rejected query: {guard.reason}")
            trail.append({"type": "query_rejected", "query": raw_query, "reason": guard.reason})
            return {"error": f"Query rejected by safety validator: {guard.reason}",
                    "hint": "Submit a single read-only query without control commands or external data sources."}

        result = await kql_runner.execute_kql(guard.query, guard.timespan_hours)
        row_count = result.get("row_count", 0)
        trail.append({
            "type": "query",
            "hypothesis": args.get("hypothesis", ""),
            "query": guard.query,
            "timespan_hours": guard.timespan_hours,
            "row_count": row_count,
            "guard_notes": guard.notes,
        })
        return {
            "row_count": row_count,
            "rows": [r for t in result.get("tables", []) for r in t.get("rows", [])][:40],
            "note": ("No rows. The table may hold no data in this workspace; this is an "
                     "evidence gap, not evidence of benignity.") if not row_count else None,
            "guard_notes": guard.notes or None,
        }

    if name == "check_ip_reputation":
        ip = args.get("ip_address", "")
        res = await threat_intel_service.lookup_ip_reputation(ip)
        trail.append({"type": "threat_intel", "indicator": ip, "verdict": res.get("verdict")})
        return res

    if name == "list_available_tables":
        res = await _list_tables()
        trail.append({"type": "table_discovery", "tables_found": res.get("count", 0)})
        return res

    return {"error": f"Unknown tool '{name}'"}


async def investigate(
    client,
    model: str,
    incident: Dict[str, Any],
    prior_enrichment: Dict[str, Any],
    notify: Optional[Callable] = None,
) -> Optional[Dict[str, Any]]:
    """
    Run the adaptive loop. Returns the parsed report, or None if the model never
    produced one - in which case the caller should fall back to the fixed pipeline
    rather than failing the triage.
    """
    trail: List[Dict[str, Any]] = []
    queries_used = 0
    tokens_used = 0

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": INVESTIGATOR_SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps({
            "incident": incident,
            "enrichment_already_performed": prior_enrichment,
            "budget": {"max_queries": MAX_QUERIES, "max_steps": MAX_STEPS},
        }, default=str)},
    ]

    for step in range(MAX_STEPS):
        budget_spent = queries_used >= MAX_QUERIES or tokens_used >= MAX_TOKENS_TOTAL
        if budget_spent:
            messages.append({
                "role": "user",
                "content": "Investigation budget is exhausted. Return the final JSON report now, "
                           "recording anything you could not establish in evidence_gaps.",
            })

        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=None if budget_spent else INVESTIGATOR_TOOLS,
                response_format={"type": "json_object"} if budget_spent else None,
                max_completion_tokens=16000,
            )
        except Exception as e:
            logger.error(f"[investigator] model call failed at step {step}: {e}")
            return None

        usage = getattr(response, "usage", None)
        if usage:
            tokens_used += getattr(usage, "total_tokens", 0) or 0

        choice = response.choices[0]
        message = choice.message
        tool_calls = getattr(message, "tool_calls", None)

        if not tool_calls:
            content = (message.content or "").strip()
            if not content:
                logger.warning(f"[investigator] empty response at step {step}")
                return None
            try:
                report = json.loads(content)
            except json.JSONDecodeError:
                # The model answered in prose. Ask once for the JSON it was told to produce.
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content": "Return that as the JSON report object only."})
                continue
            report["investigation_trail"] = trail
            report["investigation_steps"] = step + 1
            report["queries_executed"] = queries_used
            report["investigator_tokens"] = tokens_used
            return report

        messages.append({
            "role": "assistant",
            "content": message.content or "",
            "tool_calls": [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in tool_calls
            ],
        })

        for tc in tool_calls:
            name = tc.function.name
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}

            if name == "run_kql_query":
                queries_used += 1
                if notify:
                    await notify("KQL_EXECUTION",
                                 f"[step {step + 1}] {args.get('hypothesis', 'querying')}: "
                                 f"{str(args.get('query', ''))[:160]}",
                                 {"query": args.get("query"), "hypothesis": args.get("hypothesis")})

            result = await _dispatch(name, args, trail)

            if notify and name == "run_kql_query":
                rc = result.get("row_count", 0)
                await notify("KQL_RESULT",
                             f"[step {step + 1}] returned {rc} row(s)" if rc
                             else f"[step {step + 1}] no rows - recorded as an evidence gap",
                             result)

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": json.dumps(result, default=str)[:6000],
            })

    logger.warning("[investigator] step budget exhausted without a final report")
    return None
