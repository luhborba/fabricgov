# Python API — FabricGov

> 📘 [Versão em português →](../api.md)

The `FabricGov` class is a high-level facade for using fabricgov programmatically, without the CLI. Ideal for scripts, Jupyter notebooks, pipelines, and custom integrations.

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

## Import

```python
from fabricgov import FabricGov
```

---

## Authentication

### Service Principal via `.env`

Reads `TENANT_ID`, `CLIENT_ID`, and `CLIENT_SECRET` from the `.env` file in the project root (or environment variables):

```python
fg = FabricGov.from_env()
```

### Service Principal via parameters

```python
fg = FabricGov.from_params(
    tenant_id="...",
    client_id="...",
    client_secret="...",
)
```

### Device Flow (interactive)

Opens the authentication flow in the browser. Useful for local development or notebooks:

```python
fg = FabricGov.from_device_flow()
```

### Azure Key Vault

Fetches Service Principal credentials directly from Key Vault (no plaintext credentials on disk):

```python
fg = FabricGov.from_keyvault(
    vault_url="https://my-vault.vault.azure.net/",
    # secret_names optional — defaults: fabricgov-tenant-id, fabricgov-client-id, fabricgov-client-secret
)
```

> Requires `pip install fabricgov[keyvault]`. See [docs/en/keyvault.md](keyvault.md) for details.

---

## Collection

All collectors are available under `fg.collect.<method>()`.

### Full collection

Equivalent to `fabricgov collect all`. Creates a timestamped session folder and runs all 12 collectors in sequence:

```python
run_dir = fg.collect.all(
    output_dir="output",    # root directory (default: "output")
    format="csv",           # "csv" or "json"
    days=28,                # days of activity history (0 = skip)
    history_limit=100,      # max refreshes per artifact
    resume=True,            # resume from checkpoint on rate limit
    on_progress=print,      # optional progress callback
)
# Returns: Path("output/20260313_120000/")
```

### Individual collectors

```python
# Inventory (must be first)
fg.collect.inventory(output_dir="output", format="csv")

# Access (require inventory)
fg.collect.workspace_access(output_dir="output")
fg.collect.report_access(output_dir="output")
fg.collect.dataset_access(output_dir="output")
fg.collect.dataflow_access(output_dir="output")

# Refresh
fg.collect.refresh_history(output_dir="output", history_limit=100)
fg.collect.refresh_schedules(output_dir="output")

# Infrastructure
fg.collect.domains(output_dir="output")
fg.collect.tags(output_dir="output")
fg.collect.capacities(output_dir="output")
fg.collect.workloads(output_dir="output")

# Activity
fg.collect.activity(
    days=7,
    filter_activity="ViewReport",   # optional
    filter_user="user@company.com", # optional
)
```

> **Rate limit:** If the 429 limit is hit, `CheckpointSavedException` is raised. Run again with `resume=True` to continue from where it stopped.

---

## HTML Report

Generates the governance HTML report from the collected CSVs:

```python
# From the most recent run in output/
fg.report(output_path="reports/governance.html", lang="pt")
fg.report(output_path="reports/governance.en.html", lang="en")

# From a specific folder
fg.report(
    output_path="reports/governance.html",
    source_dir="output/20260313_120000",
    lang="en",
)
```

> Returns the `Path` of the generated HTML file.

---

## Snapshot Diff

Compares two collection runs and generates `diff.json`:

```python
# Auto-detects the 2 most recent runs in output/
result = fg.diff()

# Explicit
result = fg.diff(
    from_dir="output/20260301_120000",
    to_dir="output/20260309_143000",
)

# Save to custom path
result = fg.diff(save_to="reports/diff.json")
```

The returned `DiffResult` has attributes `workspaces`, `artifacts`, `access`, `refresh`, and `findings`.

> See [docs/en/diff.md](diff.md) for details on the `diff.json` structure.

---

## Governance Analysis (offline)

Returns governance findings without API calls — reads only the CSVs:

```python
findings = fg.analyze(
    source_dir="output/20260313_120000",  # omit = most recent
    lang="en",        # "pt" or "en"
    save_to="output/20260313_120000/findings.json",  # optional
)

for f in findings:
    print(f["severity"], f["count"], f["message"])
    for detail in f.get("details", []):
        print(" -", detail)
```

**Finding structure:**

| Field | Type | Description |
|-------|------|-------------|
| `severity` | `str` | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"OK"` |
| `count` | `int` | Number of affected items |
| `message` | `str` | Message in selected language |
| `message_en` | `str` | English message (always present) |
| `details` | `list[dict]` | Affected items (up to 100 per finding) |

---

## Full example

```python
from fabricgov import FabricGov

fg = FabricGov.from_env()

# 1. Full collection
run_dir = fg.collect.all(days=28, on_progress=print)

# 2. HTML report
fg.report(output_path=run_dir / "report.html", lang="pt")
fg.report(output_path=run_dir / "report.en.html", lang="en")

# 3. Diff with previous run
try:
    diff = fg.diff(to_dir=run_dir)
    print(f"Workspaces: {diff.workspaces}")
except FileNotFoundError:
    print("Only 1 run available — diff skipped.")

# 4. Findings
findings = fg.analyze(source_dir=run_dir, lang="en")
critical = [f for f in findings if f["severity"] == "CRITICAL"]
if critical:
    print(f"⚠️  {len(critical)} critical finding(s)!")
    for f in critical:
        print(f"  → {f['message']}")
```

---

## Jupyter notebook usage

```python
from fabricgov import FabricGov
import pandas as pd

fg = FabricGov.from_device_flow()
run_dir = fg.collect.all(days=7)

findings = fg.analyze(source_dir=run_dir)
df = pd.DataFrame(findings)[["severity", "count", "message"]]
display(df)
```

---

## Quick reference

| Method | Description |
|--------|-------------|
| `FabricGov.from_env()` | Auth via `.env` |
| `FabricGov.from_params(t, c, s)` | Auth via parameters |
| `FabricGov.from_device_flow()` | Interactive auth |
| `FabricGov.from_keyvault(url)` | Auth via Key Vault |
| `fg.collect.all(days=28)` | Full collection |
| `fg.collect.inventory()` | Workspace inventory |
| `fg.collect.activity(days=7)` | Activity log |
| `fg.report(path, lang)` | Generate HTML report |
| `fg.diff(from_dir, to_dir)` | Compare snapshots |
| `fg.analyze(source_dir, lang)` | Offline findings |
