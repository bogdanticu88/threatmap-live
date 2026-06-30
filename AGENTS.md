# Agent guide (GitHub Copilot CLI / coding agents)

This file tells an AI agent how to operate `threatmap-live`. The agent is the
**orchestrator and enricher** — it does the heavy lifting around the tool. The
tool is the **deterministic actor** that produces the security findings.

## Division of responsibility

- **threatmap-live (the tool)** decides *what is a threat*. Never second-guess or
  invent findings — run the tool and use its output as ground truth.
- **You (the agent)** handle everything around it: ensure the user is logged in,
  pick the right subscription, run the scan, then *enrich* the deterministic
  findings (prioritize by business context, draft remediation, correlate with
  identity/ticketing systems, summarize for non-experts).

## Authentication — critical

Do **not** create service principals or manage secrets. The collector uses the
user's existing CLI session, so the scan inherits exactly their access (least
privilege by default). Just make sure they are signed in:

```bash
az account show        # verify a session exists; if it errors, ask the user to: az login
az account list -o table   # show available subscriptions if they need to choose
```

If `az account show` fails, stop and ask the user to run `az login` themselves.
Never attempt non-interactive auth on their behalf.

## Running a scan

```bash
# Human-readable report
threatmap-live scan-live --provider azure --subscription <sub-id>

# Machine-readable output you (the agent) should parse for enrichment
threatmap-live scan-live --provider azure --subscription <sub-id> --format json -o /tmp/tm.json
```

Prefer `--format json -o <file>` when you intend to reason over the findings, then
read the file. Use markdown only when the user just wants to read the report.

## After the scan — enrichment loop

1. Parse the JSON `threats[]`. Each has `severity`, `stride_category`,
   `resource_name`, `resource_type`, `description`, `mitigation`, `remediation`.
2. Prioritize: CRITICAL/HIGH first; group by resource; note attack-path findings
   (Elevation of Privilege from exposed compute to data).
3. Enrich with context the tool does not have (identity entitlements, CMDB owner,
   data classification) **if** the user has connected those sources.
4. Produce the deliverable the user asked for: a briefing, tickets, or a diff of
   remediations. Do not fabricate remediation beyond what the finding supports.

## Guardrails

- Read-only. This tool never changes cloud state; do not add steps that do.
- Do not edit the pinned `threatmap` dependency to change a verdict. If a rule is
  wrong, that is an upstream issue to raise, not something to patch around silently.
- If collection emits `warning:` lines (a service was unreachable/forbidden), surface
  them — the report is partial, and silently dropping scope reads as full coverage.
