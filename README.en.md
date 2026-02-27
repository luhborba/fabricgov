# fabricgov

> Python library for automated governance assessment in Microsoft Fabric environments

[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Poetry](https://img.shields.io/badge/poetry-1.8+-purple.svg)](https://python-poetry.org/)
[![PyPI version](https://badge.fury.io/py/fabricgov.svg)](https://pypi.org/project/fabricgov/)

> 🇧🇷 **Documentação em Português:** [README.md](README.md)

---

## 🎯 What is it?

**fabricgov** automates governance data collection in Microsoft Fabric via CLI or Python.

**Main features:**
- 🔍 Full inventory of workspaces and 27+ artifact types
- 🔐 Access collection (workspaces, reports, datasets, dataflows)
- 🔄 Refresh history and configured schedules
- 🏢 Tenant domains, tags, capacities, and workloads
- 💾 Checkpoint system for large tenants (resumes where it left off)
- 📊 Export to JSON or CSV
- ⚡ Ready-to-use CLI
- 🛡️ Automatic rate limit handling

---

## 📦 Installation
```bash
# Via pip (recommended)
pip install fabricgov

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
# Create a .env file in the project root
FABRICGOV_TENANT_ID=your-tenant-id
FABRICGOV_CLIENT_ID=your-client-id
FABRICGOV_CLIENT_SECRET=your-client-secret
```
```bash
fabricgov auth sp       # validate credentials
```

#### Device Flow (manual use / local development)
```bash
fabricgov auth device   # opens interactive browser flow (no .env required)
```

> 📘 [Full authentication guide →](docs/en/authentication.md)

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
# Collect inventory
fabricgov collect inventory

# Collect access (with automatic checkpoint)
fabricgov collect workspace-access
fabricgov collect report-access
fabricgov collect dataset-access
fabricgov collect dataflow-access
fabricgov collect all-access      # all access collectors at once

# Collect refresh data
fabricgov collect refresh-history
fabricgov collect refresh-schedules
fabricgov collect all-refresh     # history + schedules

# Collect infrastructure
fabricgov collect domains
fabricgov collect tags
fabricgov collect capacities
fabricgov collect workloads

# Full collection in a single session
fabricgov collect all
fabricgov collect status          # check session status
```

**Available flags:**
- `--format json|csv` (default: csv)
- `--output DIR` (default: output)
- `--resume/--no-resume` (default: resume enabled)

---

### 3. Or use as a Python library
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exporters import FileExporter

# Authenticate
auth = ServicePrincipalAuth.from_env()

# Collect inventory
collector = WorkspaceInventoryCollector(auth=auth)
result = collector.collect()

# Export
exporter = FileExporter(format="csv", output_dir="output")
exporter.export(result, [])
```

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

> 📘 [See detailed examples →](docs/en/collectors.md)

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
├── collectors/         # 11 collectors (access, refresh, infrastructure)
├── exporters/          # JSON/CSV export
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
    └── workloads_errors.csv
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

### ✅ v0.6.1 (Current)
- [x] English documentation (`docs/en/`)
- [x] English README

### 🎯 v0.7.0
- [ ] HTML Report

### 🎯 v0.8.0
- [ ] Identify datasets without owners
- [ ] External users with access to sensitive workspaces
- [ ] Workspaces without refresh in the last 30 days
- [ ] CLI: `fabricgov analyze`

### 🎯 v0.9.0
- [ ] Azure Key Vault integration
- [ ] Snapshot comparison — `fabricgov diff`

### 🎯 v1.0.0
- [ ] Updated HTML Report
- [ ] MkDocs documentation

> 📘 [View full changelog →](CHANGELOG.md)

---

## 📚 Documentation

- **[Authentication](docs/en/authentication.md)** — Service Principal setup
- **[Collectors](docs/en/collectors.md)** — Examples and use cases
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
