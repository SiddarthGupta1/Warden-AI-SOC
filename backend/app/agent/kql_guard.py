"""
Safety validator for model-generated KQL.

When the agent writes its own queries, the workspace is no longer being sent a
fixed set of statements a human reviewed. Three risks follow, and this module
addresses each before the query reaches Log Analytics:

  1. Mutation. Kusto control commands (.create, .drop, .set-or-append, .ingest)
     can alter or destroy data. Log Analytics rejects most of these over the query
     API, but relying on the far side to refuse is not a control.
  2. Exfiltration and SSRF. `externaldata` and some `evaluate` plugins can pull
     from, or reach out to, arbitrary URIs from inside the query engine.
  3. Cost and denial of service. An unbounded scan over a large workspace is slow
     and billable. Every query is forced to carry a row cap.

The validator is deliberately a denylist for dangerous constructs plus a mandatory
row cap, rather than an attempt to parse Kusto. A parser would be the stronger
control; it is also a large piece of work, and the operations that matter here are
few and lexically distinctive.
"""

import re
from dataclasses import dataclass
from typing import List, Optional

MAX_ROWS = 100
MAX_TIMESPAN_HOURS = 168  # 7 days
MAX_QUERY_LENGTH = 4000

# Control commands: anything beginning with a dot at statement start.
_CONTROL_COMMAND = re.compile(r"(?:^|\n|;)\s*\.\w+", re.IGNORECASE)

# Constructs that read from, or reach out to, somewhere other than the workspace.
_FORBIDDEN = [
    (re.compile(r"\bexternaldata\b", re.I), "externaldata can read from arbitrary URIs"),
    (re.compile(r"\bevaluate\s+http_request", re.I), "http_request can make outbound calls from the query engine"),
    (re.compile(r"\bevaluate\s+sql_request", re.I), "sql_request can reach external databases"),
    (re.compile(r"\bevaluate\s+cosmosdb_sql_request", re.I), "cosmosdb_sql_request can reach external databases"),
    (re.compile(r"\bingest\s+into\b", re.I), "ingest writes data into the workspace"),
    (re.compile(r"\bcluster\s*\(", re.I), "cross-cluster queries reach outside this workspace"),
]

# Operators that already bound the result set, so no extra cap is needed.
_BOUNDING = re.compile(r"\|\s*(take|limit|top|top-nested|summarize|count|distinct)\b", re.I)


@dataclass
class GuardResult:
    ok: bool
    query: str                      # possibly rewritten (row cap appended)
    timespan_hours: int
    reason: Optional[str] = None    # why it was rejected
    notes: List[str] = None         # non-fatal modifications applied

    def __post_init__(self):
        if self.notes is None:
            self.notes = []


def validate_kql(query: str, timespan_hours: int = 24) -> GuardResult:
    """Validate and, where safe, normalise a model-generated KQL query."""
    q = (query or "").strip()
    notes: List[str] = []

    if not q:
        return GuardResult(False, q, timespan_hours, "empty query")

    if len(q) > MAX_QUERY_LENGTH:
        return GuardResult(False, q, timespan_hours,
                           f"query exceeds {MAX_QUERY_LENGTH} characters")

    if _CONTROL_COMMAND.search(q):
        return GuardResult(False, q, timespan_hours,
                           "Kusto control commands (leading '.') are not permitted; this interface is read-only")

    for pattern, why in _FORBIDDEN:
        if pattern.search(q):
            return GuardResult(False, q, timespan_hours, f"forbidden construct: {why}")

    # Multiple statements let a benign-looking prefix carry a second, unreviewed
    # statement. Let-bindings are a legitimate exception.
    statements = [s for s in q.split(";") if s.strip()]
    if len(statements) > 1 and not all(s.strip().lower().startswith("let ") for s in statements[:-1]):
        return GuardResult(False, q, timespan_hours,
                           "multiple statements are not permitted; submit one query")

    # Clamp the time window rather than rejecting, so an over-wide request still
    # returns something useful.
    ts = int(timespan_hours or 24)
    if ts < 1:
        ts, _ = 1, notes.append("timespan raised to the 1 hour minimum")
    if ts > MAX_TIMESPAN_HOURS:
        notes.append(f"timespan clamped from {ts}h to {MAX_TIMESPAN_HOURS}h")
        ts = MAX_TIMESPAN_HOURS

    # Force a row cap on anything that does not already bound its output.
    if not _BOUNDING.search(q):
        q = f"{q}\n| take {MAX_ROWS}"
        notes.append(f"row cap of {MAX_ROWS} applied")

    return GuardResult(True, q, ts, None, notes)
