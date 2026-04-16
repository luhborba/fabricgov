# fabricgov

> Python library for automated governance assessment in Microsoft Fabric environments

[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Poetry](https://img.shields.io/badge/poetry-1.8+-purple.svg)](https://python-poetry.org/)
[![PyPI version](https://badge.fury.io/py/fabricgov.svg)](https://pypi.org/project/fabricgov/)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://luhborba.github.io/fabricgov/)

> 🇧🇷 **Documentação em Português:** [README.md](README.md) | 📚 **Full documentation:** [luhborba.github.io/fabricgov](https://luhborba.github.io/fabricgov/)

---

## 🎯 What is it?

**fabricgov** automates governance data collection in Microsoft Fabric via CLI or Python.

**Main features:**
- 🔍 Full inventory of workspaces and 27+ artifact types
- 🔐 Per-artifact access collection via Scanner API — `artifact_users` in the inventory result
- 🗄️ Datasources and semantic models (tables, columns, measures, DAX) extracted automatically
- 🔄 Refresh history and configured schedules
- 🏢 Tenant domains, tags, capacities, and workloads
- 📋 Tenant activity log — up to 28 days of history
- 💾 Checkpoint system for large tenants (resumes where it left off)
- 📊 Export to JSON or CSV
- 📄 Automatic HTML report with charts and governance findings (PT + EN)
- 🔍 Terminal governance analysis via `fabricgov analyze` (no API calls)
- 🔁 Snapshot comparison via `fabricgov diff` — diff.json with all dimensions
- 🔑 Azure Key Vault integration — credentials without plain-text on disk
- ⚡ Ready-to-use CLI
- 🛡️ Automatic rate limit handling

---

## 📦 Installation
```bash
# Standard installation
pip install fabricgov

# With Azure Key Vault support
pip install fabricgov[keyvault]

# Or via Poetry
poetry add fabricgov

# CLI becomes available
fabricgov --help
```

---

## 🚀 Quick Start

### 1. Authentication

Choose the method that fits your scenario:

#### Service Principal (automation / CI-CD)
```env
# Copy the template and fill in your credentials
cp .env-example .env
# FABRICGOV_TENANT_ID=your-tenant-id
# FABRICGOV_CLIENT_ID=your-client-id
# FABRICGOV_CLIENT_SECRET=your-client-secret
```
```bash
fabricgov auth sp       # validate credentials
```

#### Device Flow (manual use / local development)
```bash
fabricgov auth device   # opens interactive browser flow (no .env required)
```

#### Azure Key Vault (production / no credentials on disk)
```bash
pip install fabricgov[keyvault]
fabricgov auth keyvault --vault-url https://my-vault.vault.azure.net/
```

> 📘 [Full authentication guide →](docs/en/authentication.md) | [Key Vault →](docs/en/keyvault.md)

#### Required permissions

| Authentication | Required permission | Where to configure |
|---|---|---|
| Service Principal | `Tenant.Read.All` + `Workspace.ReadWrite.All` (Application) | Azure AD → App Registrations → API Permissions |
| Service Principal | Enabled in Fabric Admin APIs | Fabric Admin Portal → Tenant settings |
| Device Flow | **Fabric Administrator** role in the tenant | Fabric Admin Portal → Users |

> ⚠️ Without these permissions, collections will return `403 Forbidden`.

---

### 2. Use the CLI
```bash
# Collect inventory (includes artifact_users, datasources and semantic_models)
fabricgov collect inventory

# Collect workspace access (with automatic checkpoint)
fabricgov collect workspace-access
fabricgov collect all-access      # shortcut for workspace-access

# Collect refresh data
fabricgov collect refresh-history
fabricgov collect refresh-schedules
fabricgov collect all-refresh     # history + schedules

# Collect infrastructure
fabricgov collect domains
fabricgov collect tags
fabricgov collect capacities
fabricgov collect workloads

# Collect activity log
fabricgov collect activity               # last 7 days
fabricgov collect activity --days 28     # maximum history (28 days)

# Full collection in a single session
fabricgov collect all
fabricgov collect all --days 28  # includes activity log (28 days)
fabricgov collect status         # check session status

# Snapshot comparison
fabricgov diff                                                  # 2 most recent runs
fabricgov diff --from output/20260301_120000 --to output/20260309_143000
```

> ℹ️ The `report-access`, `dataset-access` and `dataflow-access` commands were removed in v1.1.0.
> Per-artifact access data is now available directly in `artifact_users`
> after `fabricgov collect inventory`.

**Available flags:**
- `--format json|csv` (default: csv)
- `--output DIR` (default: output)
- `--resume/--no-resume` (default: resume enabled)

---

### 4. Analyze governance findings (terminal)
```bash
fabricgov analyze                                           # most recent folder in output/
fabricgov analyze --from output/20260227_143000/            # specific folder
fabricgov analyze --from output/20260227_143000/ --lang en  # messages in English
```

Displays findings directly in the terminal (without opening the HTML) and saves `findings.json` in the source folder.

---

### 3. Generate the governance report
```bash
fabricgov report                                      # most recent folder in output/
fabricgov report --from output/20260227_143000/       # specific folder
fabricgov report --from output/20260227_143000/ --open  # generate and open in browser
```

Automatically generates two standalone HTML files:
- `report.html` — English
- `report.en.html` — English (alternate filename for compatibility)

> 📘 [Full report guide →](docs/en/report.md) — sections, data sources, and rules applied

---

### 5. Or use as a Python library

The `FabricGov` class provides a high-level API — no CLI, no manual auth/exporter setup:

```python
from fabricgov import FabricGov

# Authenticate via .env (TENANT_ID, CLIENT_ID, CLIENT_SECRET)
fg = FabricGov.from_env()

# Full collection in a session folder (equivalent to 'collect all')
run_dir = fg.collect.all(days=28)

# Generate HTML report
fg.report(output_path=run_dir / "report.en.html", lang="en")

# Compare the two most recent runs
result = fg.diff()

# Governance findings (no API calls)
findings = fg.analyze(source_dir=run_dir)
for f in findings:
    print(f["severity"], f["count"], f["message"])
```

> 📘 [See full Python API documentation →](docs/en/api.md)

---

## 📊 Available Collectors

| Collector | What it collects | Checkpoint |
|-----------|-----------------|------------|
| `WorkspaceInventoryCollector` | Full inventory (workspaces + 27 artifact types) | ✅ |
| `WorkspaceAccessCollector` | Roles (Admin, Member, Contributor, Viewer) | ✅ |
| `ReportAccessCollector` | Report permissions | ✅ |
| `DatasetAccessCollector` | Dataset permissions | ✅ |
| `DataflowAccessCollector` | Dataflow permissions | ✅ |
| `RefreshHistoryCollector` | Dataset and dataflow execution history | — |
| `RefreshScheduleCollector` | Configured schedules (no API calls) | — |
| `DomainCollector` | Tenant domains (hierarchy, sensitivity labels) | — |
| `TagCollector` | Tenant tags (tenant or domain scope) | — |
| `CapacityCollector` | Premium/Fabric capacities (SKU, region, admins) | — |
| `WorkloadCollector` | Gen1 capacity workloads (P-SKU, A-SKU) | — |
| `ActivityCollector` | Tenant activity log (up to 28 days) | — |

> 📘 [See detailed examples →](docs/en/collectors.md) | [Activity log →](docs/en/activity.md)

---

## 💾 Checkpoint System

For large tenants, the checkpoint saves progress automatically:
```bash
# Run 1: processes 200 items, saves checkpoint
fabricgov collect report-access
# ⏹️ Rate limit reached (429)

# Wait ~1h30min

# Run 2: resumes where it left off (automatic)
fabricgov collect report-access
# ✓ Processes next 200 items...
```

**How it works:**
1. Detects rate limit (429)
2. Saves checkpoint automatically
3. Exits the script (terminal freed)
4. On next run, resumes where it left off

> 📘 [Understand rate limit limitations →](docs/en/limitations.md)

---

## 🏗️ Architecture
```
fabricgov/
├── cli/                # CLI via Click
├── auth/               # ServicePrincipalAuth + DeviceFlowAuth
├── collectors/         # 12 collectors (access, refresh, infrastructure, activity)
├── exporters/          # JSON/CSV export
├── reporters/          # HTML Report (InsightsEngine + HtmlReporter + template)
├── diff/               # Snapshot comparison (DiffEngine + comparators)
├── checkpoint.py       # Checkpoint system
└── exceptions.py       # Custom exceptions
```

---

## 📊 Output Example
```
output/
├── inventory_result.json           # Reusable across collectors
├── checkpoint_report_access.json   # Checkpoint (auto-removed on completion)
└── 20260226_143000/                # Timestamped folder
    ├── summary.json
    ├── workspaces.csv
    ├── reports.csv
    ├── workspace_access.csv
    ├── report_access.csv
    ├── dataset_access.csv
    ├── dataflow_access.csv
    ├── refresh_history.csv
    ├── refresh_schedules.csv
    ├── domains.csv
    ├── tags.csv
    ├── capacities.csv
    ├── workloads.csv
    ├── workloads_errors.csv
    ├── activity_events.csv # Tenant activity log
    ├── report.html         # Governance report (PT)
    ├── report.en.html      # Governance report (EN)
    ├── findings.json       # Governance findings (fabricgov analyze)
    └── diff.json           # Comparison with previous snapshot (fabricgov diff)
```

---

## ⚠️ Known Limitations

### Rate Limiting
- Admin APIs: ~200 requests/hour (undocumented by Microsoft)
- Large tenants: multiple runs with ~1h30min pauses
- Checkpoint allows resuming without losing progress

### Personal Workspaces
- Do not support user APIs (return 404)
- Automatically filtered (30–60% of workspaces in typical tenants)

### Performance
- 200 workspaces: ~10 min
- 663 reports: ~5h (4 runs with pauses)
- 2000+ items: requires scheduled collection

> 📘 [Full list of limitations →](docs/en/limitations.md)

---

## 🗺️ Roadmap

### ✅ v0.3.0 — 2026-02-23
- [x] Full CLI (`fabricgov` command)
- [x] DatasetAccessCollector
- [x] DataflowAccessCollector
- [x] 5 collectors with checkpoint
- [x] First release on PyPI

### ✅ v0.4.0 — 2026-02-24
- [x] RefreshHistoryCollector (execution history)
- [x] RefreshScheduleCollector (configured schedules)
- [x] CLI: `fabricgov collect refresh-history`
- [x] CLI: `fabricgov collect refresh-schedules`
- [x] CLI: `fabricgov collect all-refresh`
- [x] CLI: `fabricgov auth sp` (renamed from `auth test`)

### ✅ v0.5.0
- [x] DomainCollector (tenant domains)
- [x] TagCollector (tenant tags)
- [x] CapacityCollector (Premium/Fabric capacities)
- [x] WorkloadCollector (Gen1 capacity workloads)
- [x] CLI: `fabricgov collect domains/tags/capacities/workloads`
- [x] 11 collectors total
- [x] CLI: Orchestrators `all-infrastructure`, `all-access`, `all-refresh`, `all`
- [x] CLI: `fabricgov collect all` — full collection in a single session with checkpoint
- [x] CLI: `fabricgov collect status` — session status and pending checkpoints
- [x] Visual progress bars on access and refresh collectors

### ✅ v0.6.0
- [x] Internal documentation update (pt-BR)

### ✅ v0.6.1
- [x] English documentation (`docs/en/`)
- [x] English README

### ✅ v0.6.2
- [x] Quick Start with Device Flow and permissions table

### ✅ v0.7.0 — 2026-02-27
- [x] Standalone HTML report generated via `fabricgov report`
- [x] Two automatic versions: PT (`report.html`) + EN (`report.en.html`)
- [x] 10 interactive Plotly charts + KPI cards + governance findings
- [x] Dedicated Workspaces section with full artifact table

### ✅ v0.8.0
- [x] Identify datasets without owners
- [x] External users with workspace access
- [x] Workspaces without refresh in the last 30 days
- [x] CLI: `fabricgov analyze` — terminal findings + `findings.json`

### ✅ v0.8.1
- [x] Fixed HTML report error (Jinja2 `dict.items` conflict)
- [x] Collapsible artifact cards with name, owner, workspace and last modified date
- [x] "Top Users by Owned Artifacts" table
- [x] Optimized chart layout in Inventory section
- [x] `.env-example` file with documented variables

### ✅ v0.9.0 (Current)
- [x] Azure Key Vault integration (`fabricgov auth keyvault`)
- [x] `ActivityCollector` — tenant activity log (up to 28 days)
- [x] CLI: `fabricgov collect activity --days N`
- [x] `fabricgov collect all --days N` — includes activity log in full collection
- [x] `fabricgov diff` — compare two output snapshots (workspaces, artifacts, access, refresh, findings)

### ✅ v1.0.0
- [x] `FabricGov` Python API — high-level facade for programmatic use without CLI
- [x] HTML Report: Activity and Trends sections (with `activity_events.csv` and `diff.json` data)
- [x] MkDocs — official documentation PT + EN with Material theme, CLI Guide, Python Guide, Examples

### ✅ v1.0.1 — 2026-03-28
- [x] fix(checkpoint): guard against `None` checkpoint on rate limit — prevents crash when checkpoint is absent on 429
- [x] fix(checkpoint): fix `inner_resume` logic to correctly resume internal sub-collectors after rate limit pause

### ✅ v1.0.2 — 2026-04-06
- [x] feat(collect): show remaining cycle estimate in session summary (`collect all`)
- [x] fix(collect): remove stale checkpoint when skipping already-completed sub-collector — prevents unnecessary resumes

### ✅ v1.0.3 — 2026-04-06
- [x] chore: CHANGELOG, README (PT + EN) and `pyproject.toml` added to repository

### ✅ v1.0.4 — 2026-04-06
- [x] chore: remove company references from all files (HTML report, docs PT + EN)

### ✅ v1.1.0 — 2026-04-15
- [x] feat(inventory): `collect()` now returns `artifact_users`, `datasources` and `semantic_models` extracted directly from the Scanner API
- [x] feat(inventory): `ARTIFACT_TYPES_WITH_USERS` constant with 22 supported artifact types
- [x] refactor(inventory): `_list_all_workspaces()` filters by `type == "Workspace"`, excluding PersonalGroup
- [x] deprecate: `ReportAccessCollector`, `DatasetAccessCollector` and `DataflowAccessCollector` marked as deprecated
- [x] breaking(cli): `report-access`, `dataset-access` and `dataflow-access` commands removed from CLI

### ✅ v1.1.1 — 2026-04-15
- [x] fix(inventory): enrichment query params (`datasourceDetails`, `getArtifactUsers`, etc.) now sent as query string — the API ignored them when in the JSON body, causing `datasources.csv` and `artifact_users.csv` to never be generated
- [x] fix(inventory): `_extract_datasources` resolves `datasourceInstanceId` GUID via join with `datasourceInstances` from the scan root level
- [x] feat(report): new **Datasources** section in the HTML report with KPIs, type chart and connection table
- [x] feat(report): Access section expanded with `top_artifact_users` table and `artifact_users_by_type` chart

> 📘 [View full changelog →](CHANGELOG.md)

---

## 📚 Documentation

- **[Full documentation](https://luhborba.github.io/fabricgov/)** — MkDocs PT + EN
- **[Python API](docs/en/api.md)** — Programmatic usage with the `FabricGov` class
- **[Authentication](docs/en/authentication.md)** — Service Principal, Device Flow, Key Vault
- **[Key Vault](docs/en/keyvault.md)** — Credentials without plain-text on disk
- **[Collectors](docs/en/collectors.md)** — Examples and use cases
- **[Activity Log](docs/en/activity.md)** — Tenant activity events
- **[Snapshot Diff](docs/en/diff.md)** — Comparison between two collection runs
- **[HTML Report](docs/en/report.md)** — Sections, data sources, and governance rules
- **[Exporters](docs/en/exporters.md)** — Integration with Power BI, Pandas
- **[Limitations](docs/en/limitations.md)** — Rate limits, performance
- **[Contributing](docs/en/contributing.md)** — How to contribute

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

## 👤 Author

**Luciano Borba** — Data Engineering Consultant

---

**⭐ If this project was useful, consider starring it on GitHub!**
