# threatmap-live

Live cloud threat modeling on top of [threatmap](https://github.com/bogdanticu88/threatmap).

`threatmap` is a deterministic, rule-based threat modeler for **Infrastructure-as-Code**.
`threatmap-live` adds the missing capability: it collects your **deployed** cloud
resources and runs them through threatmap's existing STRIDE / MITRE ATT&CK / PASTA
engine — so you can threat-model what is *actually running*, not just what the
templates claim.

## How it works

```
  az / aws CLI (your SSO session)            threatmap (unchanged dependency)
  ──────────────────────────────            ────────────────────────────────
  read-only list/show  ──►  collector  ──►  Resource model  ──►  engine.run()
                            (this repo)      (terraform shape)     STRIDE/MITRE/PASTA
                                                                        │
                                                                        ▼
                                                        markdown / json / sarif / html
```

Design principles:

- **The engine is never modified.** Collectors map live cloud JSON into the *same*
  terraform-shaped `Resource` objects threatmap already analyzes (`azurerm_storage_account`
  with `allow_blob_public_access`, etc.), so the engine cannot tell a live resource
  from one parsed out of a `.tf` file. threatmap is pinned as a dependency.
- **No credentials are managed here.** Collectors shell out to the cloud CLI and rely
  on your *existing* login (`az login`). The tool inherits exactly your access — it can
  read nothing you could not read yourself. Every command is read-only.
- **The rules produce the verdict, not an LLM.** An agent (e.g. GitHub Copilot CLI) can
  drive this tool and enrich its output, but the security findings come from threatmap's
  deterministic rules.

## Install

```bash
pip install -e .
# or, for development:
pip install -e ".[dev]"
```

threatmap is pinned to a reviewed commit. In a restricted-network environment, vendor
the threatmap wheel and install it from a local path instead of git.

## Usage

Sign in first (the collector uses this session):

```bash
az login
```

Then scan live:

```bash
# Active subscription, markdown report to the terminal
threatmap-live scan-live --provider azure

# A specific subscription, written to a file
threatmap-live scan-live --provider azure --subscription <sub-id> -o report.md

# JSON for tooling, or SARIF for the GitHub Security tab
threatmap-live scan-live --provider azure --format json -o report.json

# CI gate: non-zero exit if anything CRITICAL is found
threatmap-live scan-live --provider azure --fail-on CRITICAL
```

### Coverage

**Azure** — read-only `az ... list` for: storage accounts, key vaults, network
security groups, role assignments, container registries, SQL servers, AKS clusters,
web apps, and Linux VMs → threatmap's `AZ-001`…`AZ-019` rules.

**AWS** — read-only `aws ... describe/list` for: security groups, RDS instances, EC2
instances, CloudTrail, Lambda, IAM roles, S3 buckets, EKS clusters, and KMS keys →
threatmap's `AWS-001`…`AWS-023` rules. (Some services use a list call plus best-effort
per-item enrichment — S3 bucket settings, EKS describe-cluster, KMS rotation status,
EC2 root-volume encryption.)

```bash
aws sso login            # or your usual AWS auth
threatmap-live scan-live --provider aws --region eu-west-1
```

## Viewer dashboard

A read-only, **NN-branded** dashboard for non-technical consumers. The CLI (operator
door) writes scans into a store folder; the viewer (consumer door) renders them. They
never talk to each other — they only share the store.

```bash
# 1. Operators run scans into the store
threatmap-live scan-live --provider azure --subscription <sub> --store store/
threatmap-live scan-live --provider aws --region eu-west-1 --store store/

# 2. Build the self-contained dashboard
threatmap-live build-viewer --store store/ -o viewer/index.html

# 3. Open viewer/index.html in any browser (double-click — no server needed)
```

The generated `index.html` is fully self-contained: scan data and the NN logo are
inlined, so it works offline on `file://` with no server, no Node, and no network
calls. It lists scans newest-first with severity counts, and drills into any scan with
severity summary cards, a filterable/searchable findings table, and per-finding
mitigations. `store/` and `viewer/` are generated artifacts (git-ignored).

## Development

```bash
pip install -e ".[dev]"
pytest
```

Tests run entirely against mocked `az` JSON fixtures — no cloud credentials required.
