# Activity Events Collector

Collects the tenant activity log via Power BI Admin API and exports to CSV/JSON.

> Full authentication guide: [authentication.md](authentication.md)

---

## What is collected?

Each event represents a user action in Power BI / Fabric:

| Field | Description |
|-------|-------------|
| `CreationTime` | Event UTC timestamp |
| `UserId` | User email |
| `Activity` | Activity type (e.g. `ViewReport`, `ExportArtifact`) |
| `Operation` | Operation performed |
| `ItemName` | Name of the accessed artifact |
| `ItemType` | Artifact type (`Report`, `Dashboard`, `Dataset`, etc.) |
| `WorkSpaceName` | Workspace name |
| `WorkspaceId` | Workspace UUID |
| `DatasetId` | Dataset UUID (when applicable) |
| `ReportId` | Report UUID (when applicable) |
| `IsSuccess` | Whether the operation succeeded |
| `ClientIP` | Client IP address |
| `UserAgent` | Browser/client used |

---

## API Limitations

| Limitation | Detail |
|------------|--------|
| **Max history** | **28 days** back |
| **Window per request** | `startDateTime` and `endDateTime` must be **in the same UTC day** |
| **Rate limit** | **200 req/hour** (shared with all Admin APIs) |
| **Pagination** | Mandatory via `continuationToken` |
| **`$filter`** | Only `Activity eq '...'`, `UserId eq '...'`, and `and`. No `or` or `contains` |
| **Permission** | User/SP must be **Fabric Administrator** |

---

## Basic usage

```bash
# Last 7 days (default)
fabricgov collect activity

# Maximum available history
fabricgov collect activity --days 28

# Last 3 days, ViewReport only
fabricgov collect activity --days 3 --filter-activity ViewReport

# Actions from a specific user only
fabricgov collect activity --days 7 --filter-user user@company.com

# Combine filters
fabricgov collect activity --days 1 \
  --filter-activity ExportArtifact \
  --filter-user user@company.com
```

---

## Available options

| Option | Default | Description |
|--------|---------|-------------|
| `--days N` | `7` | Number of days of history (maximum 28) |
| `--filter-activity NAME` | — | Filter by activity type |
| `--filter-user EMAIL` | — | Filter by user email |
| `--format json\|csv` | `csv` | Export format |
| `--output DIR` | `output` | Output directory |

---

## Most common activities

| Activity | Description |
|----------|-------------|
| `ViewReport` | User viewed a report |
| `ViewDashboard` | User viewed a dashboard |
| `ExportArtifact` | Data export |
| `ExportReport` | Export to PDF/PPTX |
| `ShareReport` | Report sharing |
| `DeleteReport` | Report deletion |
| `CreateReport` | Report creation |
| `PublishToWebReport` | Publish to public web |
| `ViewDataset` | Dataset access |
| `RefreshDataset` | Manual dataset refresh |

> The full list is available in the [Microsoft documentation](https://learn.microsoft.com/power-bi/admin/service-admin-auditing#activities-audited-by-power-bi).

---

## Generated output

```
output/20260309_143000/
└── activity_events.csv     # or .json with --format json
```

**Terminal summary:**
```
Total events:           18,432
Days collected:         7/7
Unique users:           142
Activity types:         23

Top activities:
  ViewReport                          12,543
  ViewDashboard                        3,210
  ExportArtifact                         987
  RefreshDataset                         412
  ShareReport                            280
```

---

## Usage as Python library

```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import ActivityCollector
from fabricgov.exporters import FileExporter

auth = ServicePrincipalAuth.from_env()

collector = ActivityCollector(
    auth=auth,
    days=7,
    filter_activity="ViewReport",   # optional
    filter_user=None,               # optional
    progress_callback=lambda msg: print(msg)
)

result = collector.collect()

print(f"Total: {result['summary']['total_events']} events")
print(f"Top activities: {result['summary']['top_activities'][:3]}")

exporter = FileExporter(format="csv", output_dir="output")
exporter.export(result, [])
```

---

## Common errors

**`403 Forbidden`**
- The user/SP does not have the **Fabric Administrator** role
- Check in the Fabric Admin Portal → Tenant settings → Admin API settings

**`400 Bad Request`**
- `startDateTime` and `endDateTime` are not in the same UTC day
- Check timezone — the API always operates in UTC

**Rate limit (`429`)**
- Wait ~1 hour and run again
- Collecting 28 days uses at least 28 requests

---

**[← Back to README](../../README.en.md)** | **[Collectors →](collectors.md)**
