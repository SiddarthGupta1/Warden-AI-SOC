# Warden

**AI triage for Microsoft Sentinel.**

An AI analyst for Microsoft Sentinel. It reads incidents, enriches their entities against
live threat intelligence, writes and runs its own KQL against Log Analytics, reaches a
verdict mapped to MITRE ATT&CK, and executes containment actions that are verified rather
than assumed.

Two things distinguish it from the usual demo of this shape:

- **It reports what it could not check.** Every report carries an `evidence_gaps` list and
  an `evidence_completeness` score derived from it. An empty query result is recorded as
  missing telemetry, never as an absence of malicious activity.
- **Its accuracy is measured, not asserted.** A labelled benchmark of 56 incidents and a
  reproducible harness live in [`backend/evals/`](backend/evals). Numbers below come from
  that harness and can be re-run.

---

## Measured performance

`gpt-5-mini`, 56 labelled incidents, 3 runs:

| Metric | Result |
|---|---|
| Verdict accuracy (4-class) | **84.8% ± 2.7%** |
| Operational accuracy (merging false-positive / benign) | **97.3%** |
| Missed threats | **0** across 44 malicious-incident evaluations |
| False alarms | 1 of 18 benign |
| MITRE technique recall / precision | 84.9% / 75.4% |
| Latency | ~35 s per incident |
| Cost | ~5,400 tokens per incident (single-pass) |
| **Run-to-run noise floor** | **5.4%** |

That last row matters more than the first. Identical configurations vary by up to 5.4% on
this dataset, so any comparison showing less than that is noise. Single-run accuracy figures
— including those quoted by most projects in this space — are one draw from a distribution.

```bash
cd backend
python -m evals.run_eval                         # score the agent
python -m evals.compare  run_a.json run_b.json   # A/B two configurations
python -m evals.stability run1.json run2.json    # measure the noise floor first
```

---

## How it works

```
Sentinel incident
      │
      ├─ entity extraction        accounts, IPs, hosts, processes, file hashes
      ├─ threat intelligence      AbuseIPDB · VirusTotal · Microsoft TI
      ├─ investigation            ─┬─ adaptive: the model writes its own KQL,
      │                            │            reads results, follows leads
      │                            └─ fixed:    entity-derived hunts (fallback)
      ├─ reasoning                verdict · MITRE mapping · evidence gaps
      ├─ write-back               report posted to the Sentinel incident
      └─ response                 verified containment, or an honest refusal
```

**Adaptive investigation.** Given the query tool directly, the model states a hypothesis,
runs a query, reads the rows, and decides what to ask next. In a live run it pulled a
`CorrelationId` out of one result and pivoted on it — a lead a fixed pipeline cannot follow.
Every query passes [`kql_guard`](backend/app/agent/kql_guard.py): read-only, single
statement, row-capped, no `externaldata` or outbound plugins. The same guard covers the
KQL Studio's Run button, so an analyst-run or model-written query gets exactly the checks
the agent's own queries get. It costs roughly 8× the tokens of a single pass, so it is
behind `ENABLE_ADAPTIVE_INVESTIGATION`.

**Verified response.** Containment executes, then re-reads the resulting state, and only
reports success if the change is confirmed. Refusals and failures are written into the
incident with the specific reason. Containment tags are applied only on verified success.

| Action | Implementation |
|---|---|
| `block_ip` | Sentinel threat-intelligence indicator, verified by read-back |
| `trigger_playbook` | Azure Logic App invoked via its callback URL, run id returned |
| `close_false_positive` | Sentinel incident classification |
| `disable_account` | Microsoft Graph `accountEnabled=false`, verified by re-read |
| `revoke_sessions` | Microsoft Graph `revokeSignInSessions` |
| `isolate_endpoint` | Defender for Endpoint machine isolation |

The last three require tenant permissions (`User.ReadWrite.All` with admin consent, and a
licensed Defender for Endpoint tenant). Without them the action returns `NOT_PERMITTED`
naming the missing permission — it does not pretend to have run. **They are also hidden
from the console** unless those permissions exist: a containment button that cannot contain
is worse than no button.

The playbook selector lists **only Logic Apps actually deployed** in the configured resource
group. In demo mode a sample catalogue is shown, labelled as samples.

---

## What was here before, and what was added

This repository began as a Sentinel triage demo. The original work established the product
shape — the FastAPI/React structure, the Sentinel and Log Analytics clients, the live
investigation stream, the KQL studio, the incident workbench UI, the report generators and
the demo mode that lets it run without Azure. That scaffolding is still the backbone and
most of the UI is unchanged.

What follows is what changed, and why.

### Corrected — features that reported success without doing the work

| Area | Before | Now |
|---|---|---|
| **SOAR containment** | `isolate_endpoint`, `revoke_sessions`, `block_ip`, `disable_account` were `pass` statements that returned a hardcoded success string and wrote *"Account Disabled / Compromise Contained"* into the live incident | Real API calls, verified by read-back, with `SUCCESS` / `SIMULATED` / `NOT_PERMITTED` / `FAILED` states and truthful audit records |
| **Playbook execution** | `trigger_playbook` generated a random run id and never contacted the Logic App | Resolves the trigger, fetches the callback URL from ARM, invokes it, returns the real run id |
| **Reasoning-model support** | Calls capped at 2,500 tokens returned HTTP 200 with *empty* content on reasoning models; the error was swallowed and the canned engine answered while the report still named the model | Raised to 16,000; a silent fallback is now surfaced by the eval harness |
| **Connection status** | Reported `CONNECTED` whenever config fields were populated, including inside a container that could not authenticate at all | Attempts a token and reports the real state, e.g. `CREDENTIAL ERROR (serving simulated data)` |
| **Auto-polling** | `ENABLE_AUTO_POLLING` was read by the settings API and implemented nowhere; nothing was ever triaged automatically | Implemented, bounded, and it reports whether the loop is actually running |
| **Confidence score** | A number the model emitted with no definition, which read *higher* when the verdict was wrong (ECE 0.106–0.180) | Redefined as `evidence_completeness`, tied to a mandatory `evidence_gaps` list (ECE 0.066–0.092) |
| **MITRE mapping** | Added inferred techniques the evidence did not support (precision 59%) | Constrained to directly evidenced techniques (precision 75%) |
| **PDF export** | The UI offered it; the backend produced `.docx`, Markdown, JSON and HTML only | Real PDF via reportlab |
| **Playbook catalogue** | Eight playbook names were hardcoded and merged into the live list; none had ever been deployed, so choosing one could only fail | Live mode lists only Logic Apps that actually exist; demo samples are labelled as samples |
| **"Escalate & Apply Containment"** | Called the same handler as "Sync RCA" — it posted a comment and neither escalated nor contained | Renamed *Escalate in Sentinel*, and it now sets the incident Active, raises severity to the AI's assessment, and tags it for review |
| **Action feedback** | Both Sentinel write-back buttons reported nothing: success was silent and errors went to `console.error`, so a working button looked broken | Busy / success / failure states with the actual reason surfaced |
| **Model routing** | `AZURE_OPENAI_DEPLOYMENT_NAME not in ["gpt-4o-mini","gpt-4o","gpt-6-astra"]` silently overrode the routed model on any deployment outside that list, defeating hybrid routing | The routed model is used; the deployment name is only a fallback |
| **KQL Studio execution** | `/kql/run` executed arbitrary KQL with no validation, while the agent's own queries were guarded — the weaker path was the one exposed to users | Same `kql_guard` on both paths |

### Added — capabilities that did not exist

- **Evaluation harness** ([`backend/evals/`](backend/evals)) — 56 labelled incidents across
  identity, endpoint, cloud, network and data, plus `run_eval`, `compare` and `stability`.
  The false positives are written to look alarming while carrying decisive benign context
  (a change ticket, an asset-inventory entry, a red-team authorisation), so the benchmark
  measures contextual reasoning rather than keyword matching.
- **Adaptive investigation loop** with a KQL safety validator.
- **Persistence** ([`backend/app/db.py`](backend/app/db.py)) — users, triage reports and an
  append-only remediation audit log in SQLite. Previously all three were process memory, so
  every restart discarded accounts, reissued temporary passwords, and lost every report.
- **Remediation audit trail**, written locally *before* the Sentinel comment, so an attempt
  survives the workspace being unreachable. Exposed at `GET /api/incidents/{id}/audit`.
- **Rate limiting** — 10/min on authentication (the brute-force surface), 20/min on triage
  (the cost surface), health probes exempt.
- **RBAC enforcement** — roles existed and issued, but nothing checked them; any analyst
  could contain hosts or rewrite Azure credentials.
- **File-hash enrichment** — VirusTotal was wired up but unreachable, because the triage
  path never extracted hashes.
- **Error boundary** — a render fault produced a blank white page indistinguishable from an
  outage. Unguarded array access on optional report fields (which are model-generated and
  not guaranteed) was a real trigger, and a 401 redirected to `/login`, a route this
  router-less SPA does not define. An expired session now explains itself.
- **CI** — was backend tests only. Now also builds the frontend with a bundle budget, builds
  the container *and runs it* against `/healthz`, and emits CycloneDX SBOMs for both stacks.
- **Renamed to Warden.** The project, container, Kubernetes namespace, loggers, browser
  storage keys and UI branding. Azure resource names were deliberately left alone — renaming
  them would mean recreating the workspace, Sentinel onboarding and analytics rule.

### Security fixes

- **Authentication bypass.** `get_current_user` fabricated a valid `User` from the token's
  own claims whenever the subject was unknown. Combined with a signing key committed to this
  repository, anyone who had read the source could mint an admin session. The unknown subject
  is now rejected, the role is read from the user store rather than the token, and disabled
  accounts are checked on every request.
- **Signing key.** No usable default remains. Every key ever published in this repository is
  blocklisted; in production the application refuses to start rather than run with one.
- **Secret exposure over the API.** The settings endpoint returned *raw* Azure, OpenAI and
  threat-intelligence keys to any admin, so every status poll placed live credentials in an
  HTTP response, the browser's memory, and anything logging or proxying that traffic. Keys
  are now always masked to a short prefix: being an admin is a reason to *set* a key, not to
  read it back. `/settings/update` is admin-only; previously any analyst could rewrite the
  platform's Azure credentials.
- **Unvalidated query execution.** `/kql/run` — reachable by any authenticated analyst and
  the target of the KQL Studio's Run button — executed arbitrary Kusto with no checks, while
  the agent's own queries were guarded. Both paths now share `kql_guard`.
- **CORS.** `["*"]` with credentials enabled, replaced with explicit origins.
- **Container.** `docker-compose.yml` no longer hardcodes a secret; a `.dockerignore` stops
  the host's `node_modules`, `venv` and local database entering the build context.
- **Kubernetes.** The manifest declared 2 replicas against in-memory state, and a rolling
  update against a ReadWriteOnce volume that would deadlock on every deploy. Now a single
  replica with a PVC and a `Recreate` strategy, with the scale-out path documented.

### Claims removed

The original README described multi-agent orchestration, a ReAct decision loop, CycloneDX
SBOM compliance, and specific MTTR and cost figures. The first two did not exist — there was
one agent running a fixed sequence. SBOMs now exist. The performance figures had no
measurement behind them and have been replaced with the benchmark above.

---

## Setup

Requires Python 3.11+ and Node 20+.

```bash
cd backend && python -m venv venv && venv\Scripts\activate && pip install -r requirements.txt
```

```bash
cd frontend && npm install && npm run build
```

Run it:

```bash
cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

It starts with no configuration at all: `DEMO_MODE` defaults on and ships four sample
incidents. **Temporary passwords for the default accounts are printed once in the startup
log** and must be reset on first login. They persist across restarts.

### Live mode

Copy `backend/.env.example` to `backend/.env` and set:

```env
SECRET_KEY=            # python -c "import secrets; print(secrets.token_urlsafe(48))"
DEMO_MODE=False

AZURE_TENANT_ID=
AZURE_SUBSCRIPTION_ID=
AZURE_RESOURCE_GROUP_NAME=
AZURE_WORKSPACE_NAME=
AZURE_WORKSPACE_ID=    # the workspace GUID, not its name
USE_MANAGED_IDENTITY=True   # uses DefaultAzureCredential, incl. your az login session

LLM_PROVIDER=azure_openai
AZURE_OPENAI_ENDPOINT=
AZURE_OPENAI_API_KEY=
AZURE_OPENAI_DEPLOYMENT_NAME=
AZURE_OPENAI_API_VERSION=2025-04-01-preview

ABUSEIPDB_API_KEY=     # free tier
VIRUSTOTAL_API_KEY=    # free tier
```

A service principal needs **Microsoft Sentinel Responder** and **Log Analytics Reader**.
Identity containment additionally needs Graph `User.ReadWrite.All` with tenant admin consent.

### Docker

```bash
docker compose up --build
```

Secrets come from `backend/.env`; the database is on a named volume. Note that
`USE_MANAGED_IDENTITY` resolves to a local `az login` session that does not exist inside a
container — in Docker the app runs with a live model over simulated incidents unless a real
managed identity is available, and it says so.

---

## Known limitations

- **Single instance.** SQLite is a single-writer store, so the Kubernetes manifest is pinned
  to one replica. Scaling out means moving [`db.py`](backend/app/db.py) to PostgreSQL; the
  storage layer is isolated there for that reason.
- **Benchmark scope.** 56 incidents is a starting point, and the decisive context is written
  into each incident's description. A stronger benchmark would place that context in
  queryable data so the agent has to *find* the change ticket rather than read it.
- **Evidence completeness is not a probability.** It reports how much of the required
  evidence was available. It is not, and after three rounds of tuning does not look like it
  will become, a reliable estimate of whether the verdict is correct.
- **Endpoint and identity containment depend on licensing** you may not have. Those actions
  fail loudly rather than silently.

---

## Layout

```
backend/
  app/
    agent/         triage agent, adaptive investigator, KQL guard, prompts, tools
    api/           incidents, triage, settings, auth
    services/      sentinel client, KQL runner, threat intel, remediation,
                   poller, report generators
    middleware/    rate limiting
    db.py          users, triage reports, audit log
  evals/           labelled dataset and evaluation harness
  tests/           30 tests
frontend/src/      React console
aks/               Kubernetes manifests incl. PVC
```

## Licence

MIT — see [LICENSE](LICENSE).
