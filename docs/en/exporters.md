# Exporters Guide

**Exporters** transform collector results into structured files. `FileExporter` is the main exporter, supporting JSON and CSV formats.

---

## 📁 FileExporter

### Overview

`FileExporter` creates a timestamped folder structure, ensuring multiple runs don't overwrite previous results.

**Output structure:**
```
output/
├── 20260219_120000/
│   ├── log.txt
│   ├── summary.json
│   ├── workspaces.csv (or .json)
│   ├── reports.csv
│   ├── datasets.csv
│   └── ...
└── 20260219_150000/
    └── ...
```

---

## 🚀 Basic Usage

### JSON
```python
from fabricgov.exporters import FileExporter

exporter = FileExporter(format="json", output_dir="output")
output_path = exporter.export(result, log_messages)

print(f"✓ Files exported to: {output_path}")
```

### CSV
```python
exporter = FileExporter(format="csv", output_dir="output")
output_path = exporter.export(result, log_messages)
```

---

## 📋 Parameters
```python
FileExporter(
    format: Literal["json", "csv"] = "json",
    output_dir: str = "output",
    run_dir: str | None = None
)
```

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `format` | `"json"` or `"csv"` | Export format | `"json"` |
| `output_dir` | `str` | Root directory where timestamped folders are created | `"output"` |
| `run_dir` | `str\|None` | Direct destination folder (no timestamp created). Used by `collect all` to keep all steps in a single folder | `None` |

**When to use `run_dir`:**
- Normal CLI usage: leave unset — `output/YYYYMMDD_HHMMSS/` is created automatically
- `fabricgov collect all`: managed internally to ensure all steps write to the same folder

---

## 📂 File Structure

### Always created

#### `log.txt`
Full execution log with progress, summary, and artifact counts.

#### `summary.json`
Always in JSON format, regardless of the chosen format.
```json
{
  "total_workspaces": 302,
  "total_items": 1367,
  "items_by_type": {
    "reports": 777,
    "datasets": 506
  },
  "scan_duration_seconds": 23.82,
  "batches_processed": 4
}
```

### Conditional files

One file per artifact type (only created if `count > 0`):
- `workspaces.json` / `workspaces.csv`
- `reports.json` / `reports.csv`
- `datasets.json` / `datasets.csv`
- `workspace_access.json` / `workspace_access.csv`
- `refresh_history.json` / `refresh_history.csv`
- `domains.json` / `domains.csv`
- `capacities.json` / `capacities.csv`
- ... (all collected types)

---

## 📊 JSON Format

- ✅ Hierarchical structure preserved
- ✅ Nested arrays and objects maintained
- ✅ UTF-8 encoding
- ✅ Pretty-printed (2-space indentation)
- ✅ Easy to import in Python, Power BI, etc.

---

## 📈 CSV Format

- ✅ Compatible with Excel, Power BI, Pandas
- ✅ Nested objects are **flattened** (e.g., `user.name` → `user_name`)
- ✅ Arrays are converted to JSON strings
- ✅ UTF-8 encoding
- ✅ Column headers included

### Flattening Example

**Original JSON:**
```json
{
  "id": "dataset-123",
  "sensitivityLabel": {
    "labelId": "label-456",
    "labelName": "Confidential"
  }
}
```

**Flattened CSV:**
```csv
id,sensitivityLabel_labelId,sensitivityLabel_labelName
dataset-123,label-456,Confidential
```

**Reading in Pandas:**
```python
import pandas as pd

df = pd.read_csv("datasets.csv")
```

---

## 🔄 Advanced Usage

### Multiple collectors in the same run
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector, WorkspaceAccessCollector
from fabricgov.exporters import FileExporter

auth = ServicePrincipalAuth.from_env()
log_messages = []

def progress(msg):
    from datetime import datetime
    ts = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(ts)
    log_messages.append(ts)

inventory_result = WorkspaceInventoryCollector(auth=auth, progress_callback=progress).collect()
access_result = WorkspaceAccessCollector(auth=auth, inventory_result=inventory_result).collect()

exporter = FileExporter(format="csv", output_dir="output")
exporter.export(inventory_result, log_messages)
exporter.export(access_result, [])
```

---

## 📦 Integration with Other Tools

### Power BI Desktop

**Import CSV:**
- Open Power BI Desktop → Get Data → Text/CSV
- Select `workspaces.csv`, `reports.csv`, etc.
- Relate via `workspace_id`

**Import JSON:**
- Get Data → JSON → Transform Data → Expand columns

---

### Python / Pandas
```python
import pandas as pd
from pathlib import Path

output_dir = Path("output/20260219_120000")

workspaces = pd.read_csv(output_dir / "workspaces.csv")
datasets = pd.read_csv(output_dir / "datasets.csv")

df = datasets.merge(
    workspaces[['id', 'name', 'capacityId']],
    left_on='workspace_id',
    right_on='id',
    suffixes=('_dataset', '_workspace')
)
```

---

### Azure Data Lake / Blob Storage
```python
from azure.storage.blob import BlobServiceClient
from pathlib import Path

blob_service = BlobServiceClient.from_connection_string(conn_str)
container_client = blob_service.get_container_client("governance")

output_dir = Path("output/20260219_120000")
for file_path in output_dir.glob("*"):
    blob_client = container_client.get_blob_client(file_path.name)
    with open(file_path, "rb") as data:
        blob_client.upload_blob(data, overwrite=True)
```

---

### SQL Database
```python
import sqlite3
import pandas as pd
from pathlib import Path

conn = sqlite3.connect("governance.db")
output_dir = Path("output/20260219_120000")

for csv_file in output_dir.glob("*.csv"):
    table_name = csv_file.stem
    df = pd.read_csv(csv_file)
    df.to_sql(table_name, conn, if_exists="replace", index=False)

conn.close()
print("✓ Data inserted into SQLite database")
```

---

## 🚧 Known Limitations

1. **CSV with nested arrays:** Arrays are converted to JSON strings — requires manual parsing
2. **Long column names:** Deeply nested objects generate names like `extendedProperties_DwProperties_endpoint`
3. **File size:** Large tenants (1000+ workspaces) may generate 50–100MB files

---

**[← Back: Collectors](collectors.md)** | **[Next: Contributing →](contributing.md)**
