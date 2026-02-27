# Governance Report — Complete Guide

> Documentation for `fabricgov report`: how to generate it, what each section shows, where data comes from, and what rules are applied.

---

## Generation

```bash
fabricgov report                                       # most recent folder in output/
fabricgov report --from output/20260227_143000/        # specific folder
fabricgov report --from output/20260227_143000/ --open # generate and open in browser
```

The command generates two standalone HTML files in the output folder:

| File | Language |
|------|----------|
| `report.html` | Portuguese |
| `report.en.html` | English |

The files are **self-contained** — no server required, shareable via email or cloud storage. Plotly and Bootstrap are loaded via CDN.

> **Required data:** at least one `.csv` or `.json` file in the output folder. Sections whose data doesn't exist are hidden automatically.

---

## Report Sections

### 1. Executive Summary

Tenant overview in colored KPI cards. Available whenever any data is present.

| KPI | Source | Rule |
|-----|--------|------|
| **Workspaces** | `summary.json` → `total_workspaces`; fallback: `len(workspaces.csv)` | Total collected workspaces |
| **Total Artifacts** | `summary.json` → `total_items`; fallback: sum of all artifact CSVs | Sum of all items across all artifact types |
| **Unique Users** | Union of `user_email` across `workspace_access.csv`, `report_access.csv`, `dataset_access.csv`, `dataflow_access.csv` | Distinct email addresses across all access files |
| **External Users** | Same access files | Emails containing `#EXT#` (Azure AD guest pattern) |
| **Datasets without Owner** | `datasets.csv` → `configuredBy` column | Rows where `configuredBy` is null or empty |
| **Refresh Success Rate** | `refresh_history.csv` → `status` column | `status == "Completed"` ÷ total rows × 100 |
| **Workspaces on Dedicated Capacity** | `workspaces.csv` → `isOnDedicatedCapacity` column | Values `true`, `1`, or `yes` (case-insensitive, type-agnostic) |

**Card color coding:**
- Blue — inventory metrics (counts)
- Yellow / Red — risk metrics (external users, no owner, failures)
- Green — health metrics (success rate, dedicated capacity)

---

### 2. Inventory

Overview of artifacts and workspaces with three charts.

#### Chart: Artifacts by Type (horizontal bar)
- **Source:** `summary.json` → `items_by_type`; fallback: row count of each artifact CSV present in the folder
- **Rule:** top 12 types by count, sorted descending
- **Recognized artifact CSVs:** `reports`, `datasets`, `dataflows`, `dashboards`, `datamarts`, `lakehouses`, `warehouses`, `notebooks`, `datasourceInstances`, `paginatedReports`, `Eventstream`, `Eventhouse`, `KQLDatabase`, `KQLDashboard`, `Reflex`, `DataPipeline`, `MirroredDatabase`, `SQLAnalyticsEndpoint`

#### Chart: Workspace Types (donut)
- **Source:** `workspaces.csv` → `type` column
- **Rule:** `value_counts()` — distribution by type (`Workspace`, `PersonalGroup`, etc.)

#### Chart: Dedicated vs Shared (donut)
- **Source:** `workspaces.csv` → `isOnDedicatedCapacity` column
- **Rule:** values `true/1/yes` = Dedicated; all others = Shared

---

### 3. Workspaces — Full Detail

Dedicated section with details for all collected workspaces. Requires `workspaces.csv`.

#### Internal KPI cards
- Total Workspaces
- On Dedicated Capacity
- On Shared Capacity
- Total Artifacts

#### Table: All Workspaces
- **Source:** `workspaces.csv` + cross-count with artifact CSVs
- **Columns:** Name, Type, State, Capacity (Dedicated/Shared), Capacity ID, Artifacts
- **Ordering:** descending by artifact count
- **How artifact count is calculated:** for each artifact CSV that contains a `workspace_id` column, count rows per workspace and accumulate

#### Chart: Top 10 Workspaces (horizontal bar)
- **Source:** cross-reference workspace_id → row count from artifact CSVs
- **Rule:** top 10 by total artifacts; names truncated at 35 characters

#### Cards: Artifacts by Type
- **Source:** `artifacts_by_type` (same as Inventory section)
- Individual cards per type with count

---

### 4. Access & Governance

Permission analysis and access exposure. Requires at least one `*_access.csv` file.

**Files read:**
- `workspace_access.csv` — workspace roles
- `report_access.csv` — report permissions
- `dataset_access.csv` — dataset permissions
- `dataflow_access.csv` — dataflow permissions

#### Chart: Role Distribution (donut)
- **Source:** `workspace_access.csv` → `role` column
- **Rule:** `value_counts()` — shows Admin, Member, Contributor, Viewer, and others

#### Chart: Principal Type (donut)
- **Source:** `workspace_access.csv` → `principal_type` column
- **Rule:** `value_counts()` — User, Group, App, ServicePrincipal, etc.

#### Table: External Users with Access (#EXT#)
- **Source:** all `*_access.csv` files → `user_email` column
- **Rule:** emails containing `#EXT#` (Azure AD B2B guests)
- **Columns:** Email, Roles (union across all files), workspace count
- **Limit:** top 50 by workspace count

#### Top 10 Users by Access
- **Source:** `workspace_access.csv`
- **Rule:** `groupby("user_email")["workspace_id"].nunique()` — count of distinct workspaces per user
- **Columns:** Email, Workspaces (count)

#### Workspaces with Only 1 User (Single Point of Failure)
- **Source:** `workspace_access.csv`
- **Rule:** `groupby("workspace_id")["user_email"].nunique() == 1` — identifies workspaces where only one email is listed
- **Limit:** top 20
- **Risk:** if that user leaves the organization, the workspace will have no administrator

---

### 5. Refresh Health

Analysis of dataset and dataflow execution history. Requires `refresh_history.csv`.

#### Chart: Refresh Status (donut)
- **Source:** `refresh_history.csv` → `status` column
- **Colors:** Completed = green, Failed = red, Unknown/Disabled = gray/orange
- **Rule:** `value_counts()` across all history records

#### Chart: Refreshes per Day — Last 30 Days (line chart)
- **Source:** `refresh_history.csv` → `start_time` column
- **Rule:** `pd.to_datetime(start_time)` → grouped by date; filtered to the last 30 days from report generation time
- **Records without valid `start_time`:** silently ignored

#### Table: Failed Refreshes
- **Source:** `refresh_history.csv`
- **Rule:** `status in ["Failed", "Error", "Disabled"]` (case-insensitive)
- **Columns:** Artifact, Workspace, Start, Status, Error (when available in `service_exception_json`)
- **Limit:** top 50 records

#### Table: Datasets without Refresh in the Last 30 Days
- **Source:** `refresh_history.csv`
- **Rule:** for each artifact (`artifact_name`), takes the most recent `start_time`; if it is older than 30 days from generation date, it appears in this list
- **Limit:** top 50 artifacts

---

### 6. Infrastructure

Analysis of tenant capacities and workloads. Requires `capacities.csv`.

#### Table: Capacities
- **Source:** `capacities.csv`
- **Available columns:** Name (`displayName`), SKU, State (`state`), Region (`region`)

#### Chart: Workspaces by Capacity (bar)
- **Source:** `workspaces.csv` → `capacityId`; cross-reference with `capacities.csv` → `displayName`
- **Rule:** `value_counts()` of `capacityId` in workspaces, mapped to capacity name

#### Chart: Capacities by SKU (bar)
- **Source:** `capacities.csv` → `sku` column
- **Rule:** `value_counts()` — P1, P2, F2, F64, A1, etc.

#### Workloads by State
- **Source:** `workloads.csv` → `state` column
- **Rule:** `value_counts()` — Enabled, Disabled, Unsupported

> **Note:** Workloads are only collected for Gen1 capacities (P-SKU and A-SKU). Fabric capacities (F-SKU) do not expose workloads via the API.

---

### 7. Tenant Domains

List of configured domains and sub-domains. Requires `domains.csv`.

- **Source:** `domains.csv`
- **Columns:** Name (`displayName`), Description (`description`), Parent Domain ID (`parentDomainId`)
- **Hierarchy rule:** if `parentDomainId` is null/empty = **Root**; otherwise = **Sub-domain**
- **Limit:** top 100 domains

---

### 8. Governance Findings

Prioritized list of alerts generated automatically based on collected data. Findings are ordered by severity and displayed even when data is partial.

| Severity | Color | Finding | Rule |
|----------|-------|---------|------|
| **CRITICAL** | Red | Datasets without owner | `configuredBy` null or empty in `datasets.csv` |
| **HIGH** | Orange | External users with access | Emails with `#EXT#` in any access file |
| **HIGH** | Orange | Failed refreshes | `status == "Failed"` in `refresh_history.csv` |
| **MEDIUM** | Blue | Workspaces with 1 unique user | `nunique(user_email) == 1` per workspace in `workspace_access.csv` |
| **MEDIUM** | Blue | Datasets without refresh in 30+ days | Most recent `start_time` > 30 days in `refresh_history.csv` |
| **OK** | Green | No critical findings | Displayed only when none of the above are detected |

> Findings only appear when the required data is available. If `refresh_history.csv` was not collected, refresh-related findings will not be generated.

---

## Data Requirements by Section

| Section | Required file(s) |
|---------|-----------------|
| Executive Summary | Any file in the folder |
| Inventory | `workspaces.csv`, `summary.json`, or artifact CSVs |
| Workspaces — Detail | `workspaces.csv` |
| Access & Governance | `workspace_access.csv` (minimum) |
| Refresh Health | `refresh_history.csv` |
| Infrastructure | `capacities.csv` |
| Domains | `domains.csv` |
| Findings | Any combination of the above |

---

## Output

Two HTML files are generated in the data source folder (or the folder specified via `--output`):

```
output/20260227_143000/
├── report.html         # Portuguese
└── report.en.html      # English
```

The HTML file is **standalone**: all Plotly charts and Bootstrap CSS are loaded via CDN. Plotly JS is included once in the document `<head>`.

---

## Limitations

- Missing sections: if a data file doesn't exist, the corresponding section displays a subtle notice ("data not available") instead of an error
- Table limits: 50 rows for failures and stale datasets; 20 for single-user workspaces; 10 for top workspaces/users
- Refresh history: the Power BI API returns only the most recent refreshes per dataset (see [limitations](limitations.md))
- Workloads: available only for Gen1 capacities (P-SKU, A-SKU)
- Charts: require CDN connectivity for Plotly and Bootstrap to render correctly

---

> 📘 [Back to README](../../README.en.md) | [Collectors Guide](collectors.md) | [Limitations](limitations.md)
