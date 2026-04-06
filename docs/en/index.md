# fabricgov

> Python library for automated governance assessment in Microsoft Fabric environments.

[![PyPI version](https://badge.fury.io/py/fabricgov.svg)](https://pypi.org/project/fabricgov/)
[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## What is it?

**fabricgov** automates governance data collection in Microsoft Fabric via CLI or Python. It combines calls to the Power BI and Microsoft Fabric APIs to extract inventory, access, refresh history, activity logs, and infrastructure into CSV/JSON files — ready for analysis and reporting.

---

## Installation

```bash
pip install fabricgov
```

For Azure Key Vault support:

```bash
pip install fabricgov[keyvault]
```

---

## Quick Start — CLI

```bash
# 1. Configure authentication
fabricgov auth sp

# 2. Collect everything
fabricgov collect all --days 7

# 3. Generate HTML report
fabricgov report --open

# 4. View governance findings in the terminal
fabricgov analyze
```

## Quick Start — Python

```python
from fabricgov import FabricGov

fg = FabricGov.from_env()
run_dir = fg.collect.all(days=28)
fg.report(output_path=run_dir / "report.en.html", lang="en")

findings = fg.analyze(source_dir=run_dir, lang="en")
for f in findings:
    print(f["severity"], f["count"], f["message"])
```

---

## Features

| Feature | Description |
|---------|-------------|
| **12 collectors** | Inventory, access, refresh, domains, tags, capacities, activity logs |
| **HTML Report** | Standalone with Plotly + Bootstrap 5, PT and EN |
| **`fabricgov analyze`** | Governance findings in the terminal + `findings.json` |
| **`fabricgov diff`** | Snapshot comparison between two output runs |
| **Python API** | `FabricGov` facade for programmatic use without CLI |
| **Checkpoint** | Automatic resume after rate limit (429) |
| **Azure Key Vault** | Credentials without plain-text on disk |

---

## Navigation

- [**Python API**](api.md) — Programmatic usage with `FabricGov`
- [**Authentication**](authentication.md) — Service Principal, Device Flow, Key Vault
- [**Collectors**](collectors.md) — All 12 available collectors
- [**Activity Log**](activity.md) — Tenant activity events
- [**Snapshot Diff**](diff.md) — Comparison between runs
- [**HTML Report**](report.md) — Sections, data sources, and governance rules
- [**Limitations**](limitations.md) — Rate limits and restrictions

---

## Author

**Luciano Borba** — [GitHub](https://github.com/luhborba) · [LinkedIn](https://linkedin.com/in/luhborba) · [YouTube](https://youtube.com/@luhborba)

Data Engineering Consultant — Microsoft Fabric & Power BI
