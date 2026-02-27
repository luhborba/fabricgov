# Collectors Guide

**Collectors** are responsible for fetching specific data from Microsoft Fabric and Power BI APIs. Each collector inherits common behaviors from `BaseCollector` (retry, pagination, rate limiting) and implements domain-specific logic.

---

## 📦 Available Collectors (v0.5.0 — 11 total)

### Inventory & Access
| Collector | CLI | Checkpoint |
|-----------|-----|------------|
| `WorkspaceInventoryCollector` | `collect inventory` | ✅ |
| `WorkspaceAccessCollector` | `collect workspace-access` | — |
| `ReportAccessCollector` | `collect report-access` | ✅ |
| `DatasetAccessCollector` | `collect dataset-access` | ✅ |
| `DataflowAccessCollector` | `collect dataflow-access` | ✅ |

### Refresh
| Collector | CLI | Checkpoint |
|-----------|-----|------------|
| `RefreshHistoryCollector` | `collect refresh-history` | ✅ |
| `RefreshScheduleCollector` | `collect refresh-schedules` | — |

### Infrastructure
| Collector | CLI | Checkpoint |
|-----------|-----|------------|
| `DomainCollector` | `collect domains` | — |
| `TagCollector` | `collect tags` | — |
| `CapacityCollector` | `collect capacities` | — |
| `WorkloadCollector` | `collect workloads` | — |

---

## 🔍 WorkspaceInventoryCollector

### What it collects

- **Workspaces:** metadata for all workspaces in the tenant
- **27+ artifact types:**
  - `datasets` — Semantic Models / Datasets
  - `reports` — Power BI Reports
  - `dashboards` — Power BI Dashboards
  - `dataflows` — Dataflows Gen1 and Gen2
  - `datamarts` — Datamarts
  - `lakehouses` — Lakehouses
  - `warehouses` — Data Warehouses
  - `notebooks` — Notebooks
  - `sparkJobDefinitions` — Spark Job Definitions
  - `mlModels` — ML Models
  - `mlExperiments` — ML Experiments
  - `kqlDatabases` — KQL Databases
  - `kqlQuerysets` — KQL Querysets
  - `eventstreams` — Eventstreams
  - `reflex` — Reflex
  - `semanticModels` — Semantic Models
  - `sqlEndpoints` — SQL Endpoints
  - `mirroredDatabases` — Mirrored Databases
  - `mirroredWarehouses` — Mirrored Warehouses
  - `graphqlApis` — GraphQL APIs
  - `sqlDatabases` — SQL Databases
  - `variableLibraries` — Variable Libraries
  - `paginatedReports` — Paginated Reports
  - `deploymentPipelines` — Deployment Pipelines
  - `workbooks` — Excel Workbooks
- **Datasources:**
  - `datasourceInstances` — Configured datasources
  - `misconfiguredDatasourceInstances` — Misconfigured datasources

---

### How it works

**Internal flow:**

1. **GET** `/v1.0/myorg/admin/groups` → Lists all workspace IDs
2. **Split into batches of 100** (API scan limit)
3. For each batch:
   - **POST** `/v1.0/myorg/admin/workspaces/getInfo` → Starts async scan
   - **Polling** on `/scanStatus/{scanId}` until status = `Succeeded`
   - **GET** `/scanResult/{scanId}` → Retrieves results
4. **Aggregates** all results and extracts artifacts by type

---

### Constructor Parameters
```python
WorkspaceInventoryCollector(
    auth: AuthProvider,
    progress_callback: Callable[[str], None] | None = None,
    poll_interval: int = 5,
    max_poll_time: int = 600,
    **kwargs
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `auth` | `AuthProvider` | ServicePrincipalAuth or DeviceFlowAuth |
| `progress_callback` | `Callable[[str], None]` | Called on each progress update |
| `poll_interval` | `int` | Seconds between scan status checks |
| `max_poll_time` | `int` | Maximum timeout in seconds per scan |

**Inherited from BaseCollector** (via `**kwargs`):
- `timeout` — HTTP timeout in seconds (default: 30)
- `max_retries` — retries on transient errors (default: 3)
- `retry_delay` — base delay between retries (default: 1.0s)
- `request_delay` — delay between successive requests (default: 0.1s)

---

### Basic Usage
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector

auth = ServicePrincipalAuth.from_env()

collector = WorkspaceInventoryCollector(auth=auth)
result = collector.collect()

print(f"Total workspaces: {result['summary']['total_workspaces']}")
print(f"Total items: {result['summary']['total_items']}")
```

---

### Output Structure
```python
{
  "workspaces": [
    {
      "id": "workspace-guid",
      "name": "workspace-name",
      "type": "Workspace",
      "state": "Active",
      "isOnDedicatedCapacity": true,
      "capacityId": "capacity-guid",
      ...
    }
  ],
  "datasets": [
    {
      "id": "dataset-guid",
      "name": "dataset-name",
      "configuredBy": "user@domain.com",
      "workspace_id": "workspace-guid",
      "workspace_name": "workspace-name",
      "refreshSchedule": { ... },  # if configured
      ...
    }
  ],
  "reports": [...],
  // ... other artifact types
  "datasourceInstances": [...],
  "misconfiguredDatasourceInstances": [...],
  "summary": {
    "total_workspaces": 302,
    "total_items": 1367,
    "items_by_type": {
      "reports": 777,
      "datasets": 506,
      "dashboards": 65
    },
    "scan_duration_seconds": 23.82,
    "batches_processed": 4
  }
}
```

**Note:** `inventory_result` is a prerequisite for all Access Collectors and Refresh collectors.

---

### Performance

**Reference tenant (302 workspaces):**
- **Execution time:** ~24 seconds
- **Batches processed:** 4 (100 + 100 + 100 + 2)
- **Items collected:** 1,367 artifacts

---

## 🔐 WorkspaceAccessCollector

Extracts workspace access roles (Admin, Member, Contributor, Viewer) via Power BI Admin API.

### What it collects

- **Workspace roles:** Admin, Member, Contributor, Viewer
- **Users and Service Principals** with access

**Automatic filtering:** Personal Workspaces are skipped (do not support the users API).

---

### Constructor Parameters
```python
WorkspaceAccessCollector(
    auth: AuthProvider,
    inventory_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    progress_manager: ProgressManager | None = None,
    **kwargs
)
```

---

### Basic Usage
```python
from fabricgov.collectors import WorkspaceInventoryCollector, WorkspaceAccessCollector

auth = ServicePrincipalAuth.from_env()
inventory_result = WorkspaceInventoryCollector(auth=auth).collect()

result = WorkspaceAccessCollector(
    auth=auth,
    inventory_result=inventory_result
).collect()

print(f"Total access entries: {result['summary']['total_access_entries']}")
```

---

### Output Structure
```python
{
  "workspace_access": [
    {
      "workspace_id": "abc-123",
      "workspace_name": "Marketing Analytics",
      "user_email": "user@company.com",
      "user_identifier": "user-guid",
      "principal_type": "User",  # or "App"
      "role": "Admin"  # Admin, Member, Contributor, Viewer
    }
  ],
  "workspace_access_errors": [...],
  "summary": {
    "total_workspaces": 302,
    "personal_workspaces_skipped": 120,
    "workspaces_processed": 182,
    "workspaces_with_users": 88,
    "total_access_entries": 294,
    "users_count": 48,
    "service_principals_count": 7,
    "roles_breakdown": {
      "Admin": 263,
      "Member": 9,
      "Viewer": 15,
      "Contributor": 7
    },
    "rate_limit_pauses": 15,
    "errors_count": 2
  }
}
```

---

### Use Cases

#### Audit privileged access
```python
admins = [a for a in result['workspace_access'] if a['role'] == 'Admin']
print(f"Total Admins: {len(admins)}")
```

#### Workspaces with only 1 Admin (orphan risk)
```python
from collections import defaultdict

workspaces_admins = defaultdict(list)
for a in result['workspace_access']:
    if a['role'] == 'Admin':
        workspaces_admins[a['workspace_id']].append(a['user_email'])

at_risk = {ws: admins for ws, admins in workspaces_admins.items() if len(admins) == 1}
print(f"⚠️  {len(at_risk)} workspaces with only 1 Admin")
```

---

## 📄 ReportAccessCollector

Extracts report access permissions via Power BI Admin API.

### What it collects

- **Report permissions:** Owner, Read, ReadWrite, ReadCopy, ReadReshare, ReadExplore
- Checkpoint support for large tenants

---

### Constructor Parameters
```python
ReportAccessCollector(
    auth: AuthProvider,
    inventory_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    checkpoint_file: str | Path | None = None,
    progress_manager: ProgressManager | None = None,
    **kwargs
)
```

---

### Basic Usage
```python
from fabricgov.collectors import ReportAccessCollector
from fabricgov.exceptions import CheckpointSavedException

collector = ReportAccessCollector(
    auth=auth,
    inventory_result=inventory_result,
    checkpoint_file="output/checkpoint_report_access.json"
)

try:
    result = collector.collect()
except CheckpointSavedException as e:
    print(f"⏹️  {e.progress} — Run again after 1h30min")
```

---

### Output Structure
```python
{
  "report_access": [
    {
      "report_id": "report-123",
      "report_name": "Sales Dashboard",
      "workspace_id": "abc-123",
      "workspace_name": "Marketing Analytics",
      "user_email": "user@company.com",
      "user_identifier": "user-guid",
      "principal_type": "User",
      "permission": "Owner"  # Owner, Read, ReadWrite, ReadCopy, ReadReshare, ReadExplore
    }
  ],
  "report_access_errors": [...],
  "summary": {
    "total_reports": 777,
    "personal_workspaces_reports_skipped": 150,
    "reports_processed": 627,
    "reports_with_users": 400,
    "total_access_entries": 4363,
    "permissions_breakdown": { "Owner": 3945, "Read": 230, ... },
    "errors_count": 3
  }
}
```

---

## 📊 DatasetAccessCollector

Extracts dataset access permissions via Power BI Admin API.

### What it collects

- **Dataset permissions:** Read, ReadWrite, Build, Reshare
- Automatic checkpoint every 100 datasets

---

### Constructor Parameters
```python
DatasetAccessCollector(
    auth: AuthProvider,
    inventory_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    checkpoint_file: str | Path | None = None,
    progress_manager: ProgressManager | None = None,
    **kwargs
)
```

---

### Basic Usage
```python
from fabricgov.collectors import DatasetAccessCollector
from fabricgov.exceptions import CheckpointSavedException

collector = DatasetAccessCollector(
    auth=auth,
    inventory_result=inventory_result,
    checkpoint_file="output/checkpoint_dataset_access.json"
)

try:
    result = collector.collect()
except CheckpointSavedException as e:
    print(f"⏹️  {e.progress} — Run again after 1h30min")
```

---

### Output Structure
```python
{
  "dataset_access": [
    {
      "dataset_id": "dataset-123",
      "dataset_name": "Sales Data",
      "workspace_id": "abc-123",
      "workspace_name": "Marketing Analytics",
      "user_email": "user@company.com",
      "user_identifier": "user-guid",
      "principal_type": "User",
      "permission": "Read"  # Read, ReadWrite, Build, Reshare
    }
  ],
  "dataset_access_errors": [...],
  "summary": {
    "total_datasets": 506,
    "datasets_processed": 326,
    "total_access_entries": 1200,
    "permissions_breakdown": { "Read": 800, "Build": 80, ... },
    "errors_count": 2
  }
}
```

---

## 🌊 DataflowAccessCollector

Extracts dataflow access permissions via Power BI Admin API.

### What it collects

- **Dataflow permissions:** Owner, User
- Automatic checkpoint every 50 dataflows

---

### Constructor Parameters
```python
DataflowAccessCollector(
    auth: AuthProvider,
    inventory_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    checkpoint_file: str | Path | None = None,
    progress_manager: ProgressManager | None = None,
    **kwargs
)
```

---

### Basic Usage
```python
from fabricgov.collectors import DataflowAccessCollector
from fabricgov.exceptions import CheckpointSavedException

collector = DataflowAccessCollector(
    auth=auth,
    inventory_result=inventory_result,
    checkpoint_file="output/checkpoint_dataflow_access.json"
)

try:
    result = collector.collect()
except CheckpointSavedException as e:
    print(f"⏹️  {e.progress} — Run again after 1h30min")
```

---

## 🔄 RefreshHistoryCollector

Collects refresh history for datasets and dataflows via Power BI Admin API.

### What it collects

- **Datasets:** via `GET /v1.0/myorg/admin/datasets/{datasetId}/refreshes`
- **Dataflows:** via `GET /v1.0/myorg/admin/dataflows/{dataflowId}/transactions`
- Per refresh: type, status, start/end times, **calculated duration**, error details

**Automatic filtering:** Personal Workspaces are skipped.

---

### Constructor Parameters
```python
RefreshHistoryCollector(
    auth: AuthProvider,
    inventory_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    checkpoint_file: str | Path | None = None,
    history_limit: int = 100,
    progress_manager: ProgressManager | None = None,
    **kwargs
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `history_limit` | `int` | Max refreshes to collect per artifact (default: 100) |

---

### Basic Usage
```python
from fabricgov.collectors import RefreshHistoryCollector
from fabricgov.exceptions import CheckpointSavedException

collector = RefreshHistoryCollector(
    auth=auth,
    inventory_result=inventory_result,
    checkpoint_file="output/checkpoint_refresh_history.json",
    history_limit=50
)

try:
    result = collector.collect()
except CheckpointSavedException as e:
    print(f"⏹️  {e.progress} — Run again after 1h30min")
```

---

### Output Structure
```python
{
  "refresh_history": [
    {
      "artifact_type": "Dataset",          # "Dataset" or "Dataflow"
      "artifact_id": "dataset-123",
      "artifact_name": "Sales Data",
      "workspace_id": "abc-123",
      "workspace_name": "Marketing Analytics",
      "refresh_type": "Scheduled",
      "start_time": "2026-02-20T01:00:00Z",
      "end_time": "2026-02-20T01:03:24Z",
      "status": "Completed",               # Completed, Failed, Cancelled, Unknown
      "duration_seconds": 204,
      "request_id": "request-guid",
      "service_exception_json": null
    }
  ],
  "refresh_history_errors": [...],
  "summary": {
    "total_artifacts": 532,
    "total_refreshes": 18420,
    "refreshes_by_status": { "Completed": 16800, "Failed": 1200 },
    "errors_count": 12
  }
}
```

---

### Known Limitations

- **API returns a maximum of 3 days** of history for datasets (Microsoft limitation)
- Datasets with no recent refresh return **404** — logged as errors, expected behavior

---

### Use Cases

#### Identify datasets with recurring failures
```python
from collections import defaultdict

failed_by_dataset = defaultdict(int)
for refresh in result['refresh_history']:
    if refresh['status'] == 'Failed':
        failed_by_dataset[refresh['artifact_name']] += 1

top_failures = sorted(failed_by_dataset.items(), key=lambda x: -x[1])[:10]
for name, count in top_failures:
    print(f"  {name}: {count} failures")
```

---

## 📅 RefreshScheduleCollector

Extracts refresh schedule configurations from the inventory result.

### What it collects

- **Schedules for datasets and dataflows** that have a schedule configured
- Days of the week, times, timezone, notification settings
- **No API calls** — reads data already present in `inventory_result`

---

### Constructor Parameters
```python
RefreshScheduleCollector(
    auth: AuthProvider,        # Not used, but required by inheritance
    inventory_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    **kwargs
)
```

---

### Basic Usage
```python
from fabricgov.collectors import RefreshScheduleCollector

collector = RefreshScheduleCollector(
    auth=auth,
    inventory_result=inventory_result
)
result = collector.collect()

print(f"Schedules found: {result['summary']['total_schedules_found']}")
print(f"Enabled: {result['summary']['schedules_enabled']}")
```

---

### Output Structure
```python
{
  "refresh_schedules": [
    {
      "artifact_type": "Dataset",
      "artifact_id": "dataset-123",
      "artifact_name": "Sales Data",
      "workspace_id": "abc-123",
      "workspace_name": "Marketing Analytics",
      "enabled": true,
      "days": "Sunday,Monday,Tuesday,Wednesday,Thursday,Friday,Saturday",
      "times": "00:00,08:00,16:00",
      "timezone": "E. South America Standard Time",
      "notify_option": "MailOnFailure"
    }
  ],
  "summary": {
    "total_schedules_found": 312,
    "schedules_enabled": 287,
    "schedules_disabled": 25,
    "schedules_by_artifact_type": { "Dataset": 295, "Dataflow": 17 }
  }
}
```

---

## 🏢 DomainCollector

Collects all tenant domains via Fabric Admin API.

### What it collects

- **Domains:** id, name, description, hierarchy (parent/child), default sensitivity label
- API: `GET https://api.fabric.microsoft.com/v1/admin/domains`

---

### Constructor Parameters
```python
DomainCollector(
    auth: AuthProvider,
    progress_callback: Callable[[str], None] | None = None,
    non_empty_only: bool = False,
    **kwargs
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `non_empty_only` | `bool` | If `True`, returns only domains with active workspaces (default: `False`) |

---

### Basic Usage
```python
from fabricgov.collectors import DomainCollector

collector = DomainCollector(auth=auth)
result = collector.collect()

print(f"Total domains: {result['summary']['total_domains']}")
print(f"  Root domains: {result['summary']['root_domains']}")
print(f"  Sub-domains: {result['summary']['sub_domains']}")
```

---

### Output Structure
```python
{
  "domains": [
    {
      "id": "domain-guid",
      "displayName": "Data Engineering",
      "description": "Domain for data engineering",
      "parentDomainId": null,         # null = root domain
      "defaultLabelId": "label-guid"  # default sensitivity label (optional)
    }
  ],
  "summary": {
    "total_domains": 8,
    "root_domains": 3,
    "sub_domains": 5,
    "domains_with_default_label": 2
  }
}
```

---

## 🏷️ TagCollector

Collects all tenant tags via Fabric Admin API.

### What it collects

- **Tags:** id, name, scope (tenant or specific domain)
- API: `GET https://api.fabric.microsoft.com/v1/admin/tags` with automatic pagination

---

### Basic Usage
```python
from fabricgov.collectors import TagCollector

collector = TagCollector(auth=auth)
result = collector.collect()

print(f"Total tags: {result['summary']['total_tags']}")
print(f"  Tenant tags: {result['summary']['tenant_tags']}")
print(f"  Domain tags: {result['summary']['domain_tags']}")
```

---

### Output Structure
```python
{
  "tags": [
    {
      "id": "tag-guid",
      "displayName": "Production",
      "scope_type": "Tenant",        # "Tenant" or "Domain"
      "scope_domain_id": null
    }
  ],
  "summary": {
    "total_tags": 15,
    "tenant_tags": 10,
    "domain_tags": 5
  }
}
```

---

## ⚡ CapacityCollector

Collects all Premium/Fabric capacities in the tenant via Power BI Admin API.

### What it collects

- **Capacities:** id, name, SKU, state, region, admins, encryption key
- API: `GET /v1.0/myorg/admin/capacities` with pagination

---

### Basic Usage
```python
from fabricgov.collectors import CapacityCollector

collector = CapacityCollector(auth=auth)
result = collector.collect()

print(f"Capacities: {result['summary']['total_capacities']}")
print(f"  Active: {result['summary']['active']}")
print(f"  SKUs: {result['summary']['skus']}")
```

---

### Output Structure
```python
{
  "capacities": [
    {
      "id": "capacity-guid",
      "displayName": "Fabric Production",
      "sku": "F64",
      "state": "Active",              # Active, Suspended, Deleted
      "region": "Brazil South",
      "admins": ["admin@company.com"],
      "capacityUserAccessRight": "Admin"
    }
  ],
  "summary": {
    "total_capacities": 3,
    "active": 2,
    "suspended": 1,
    "skus": { "F64": 1, "P1": 1, "A1": 1 },
    "regions": { "Brazil South": 2, "East US": 1 }
  }
}
```

---

## ⚙️ WorkloadCollector

Collects workloads configured on Gen1 capacities via Power BI API.

### What it collects

- **Workloads per capacity:** Dataflows, PaginatedReports, ArtificialIntelligence, etc.
- State (Enabled, Disabled, Unsupported) and configured memory percentage
- **Gen1 capacities only** (P-SKU, A-SKU) — Fabric F-SKU capacities are automatically skipped

**Prerequisite:** requires the result from `CapacityCollector`.

---

### Constructor Parameters
```python
WorkloadCollector(
    auth: AuthProvider,
    capacities_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    **kwargs
)
```

---

### Basic Usage
```python
from fabricgov.collectors import CapacityCollector, WorkloadCollector

capacities_result = CapacityCollector(auth=auth).collect()

collector = WorkloadCollector(
    auth=auth,
    capacities_result=capacities_result
)
result = collector.collect()

print(f"Workloads collected: {result['summary']['total_workloads']}")
print(f"Gen2 capacities skipped: {result['summary']['capacities_skipped_gen2']}")
```

---

### Output Structure
```python
{
  "workloads": [
    {
      "capacity_id": "capacity-guid",
      "capacity_name": "Premium P1",
      "capacity_sku": "P1",
      "workload_name": "Dataflows",
      "state": "Enabled",
      "max_memory_percentage": 20
    }
  ],
  "workloads_errors": [...],
  "summary": {
    "total_capacities": 3,
    "capacities_processed": 2,
    "capacities_skipped_gen2": 1,
    "total_workloads": 8,
    "enabled": 5,
    "disabled": 2,
    "unsupported": 1,
    "workload_types": { "Dataflows": 2, "PaginatedReports": 2 },
    "errors": 1
  }
}
```

---

## 🖥️ CLI: Orchestrators

### `fabricgov collect all`

Runs the full collection in a single session (shared output folder):

```
inventory → all-infrastructure → all-access → all-refresh
```

**Options:**
- `--format csv|json` — output format (default: csv)
- `--output DIR` — root folder (default: output)
- `--resume/--no-resume` — resume previous session (default: enabled)
- `--limit N` — max refreshes per artifact (default: 100)
- `--progress/--no-progress` — show progress bars (default: enabled)

```bash
# Full collection
fabricgov collect all

# Resume after rate limit
fabricgov collect all --resume

# Without progress bars (useful for CI/CD or log files)
fabricgov collect all --no-progress
```

---

### `fabricgov collect status`

Shows the current session status and detected checkpoints:

```bash
fabricgov collect status
```

**Output:**
```
═══════════════════════════════════════════════════════════════════
SESSION STATUS
═══════════════════════════════════════════════════════════════════
Folder:     output/20260226_140001/
Started:    2026-02-26 14:00:01
Status:     INTERRUPTED

Steps:
  ✅ inventory            completed 14:00:45
  ✅ all-infrastructure   completed 14:01:12
  ⏹️  all-access          interrupted 14:32:18
  ⏳ all-refresh          pending

Detected checkpoints:
  💾 checkpoint_dataset_access.json

To resume: fabricgov collect all --resume
═══════════════════════════════════════════════════════════════════
```

---

## 🛠️ BaseCollector — Common Features

All collectors inherit from `BaseCollector`, which provides:

### Automatic Retry

Transient errors (429, 500, 503) are retried with **exponential backoff**:
```python
collector = WorkspaceInventoryCollector(
    auth=auth,
    max_retries=5,
    retry_delay=2.0
)
```

### Rate Limiting

Automatic delay between requests:
```python
collector = WorkspaceInventoryCollector(
    auth=auth,
    request_delay=0.5   # 500ms between requests
)
```

### Automatic Pagination

`_paginate()` handles `continuationToken` automatically:
```python
items = self._paginate(
    endpoint="/v1/workspaces",
    scope="https://api.fabric.microsoft.com/.default",
    params={"$top": 5000}
)
```

---

**[← Back: Authentication](authentication.md)** | **[Next: Exporters →](exporters.md)**
