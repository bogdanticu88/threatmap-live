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

### Coverage (Azure, slice 1)

Read-only `az ... list` for: storage accounts, key vaults, network security groups,
role assignments, container registries, SQL servers, AKS clusters, web apps, and Linux
VMs — mapped onto threatmap's existing `AZ-001`…`AZ-019` rules.

AWS is the next collector to land (`--provider aws` currently reports not-implemented).

## Development

```bash
pip install -e ".[dev]"
pytest
```

Tests run entirely against mocked `az` JSON fixtures — no cloud credentials required.
