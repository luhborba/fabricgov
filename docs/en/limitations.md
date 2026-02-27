# Technical Limitations

This document lists the known technical limitations of the **fabricgov** library, including API restrictions, performance considerations, and unsupported use cases.

---

## 📡 API Limitations

### Rate Limiting — Power BI Admin APIs

**Affected APIs:**
- `GET /admin/groups/{groupId}/users` (WorkspaceAccessCollector)
- `GET /admin/reports/{reportId}/users` (ReportAccessCollector)
- `GET /admin/datasets/{datasetId}/users` (DatasetAccessCollector)
- `GET /admin/dataflows/{dataflowId}/users` (DataflowAccessCollector)
- `GET /admin/datasets/{datasetId}/refreshes` (RefreshHistoryCollector)
- `GET /admin/dataflows/{dataflowId}/transactions` (RefreshHistoryCollector)

**Observed limit:** ~200 requests/hour (not officially documented by Microsoft)

**Behavior:**
- After ~200 requests, the API returns `429 Too Many Requests`
- The limit appears to be a **sliding window**, not a fixed 1-hour reset
- Pausing 30 seconds and retrying is **not** sufficient
- Requires a pause of **~1h30min** to fully reset

**Impact:**
- Small tenants (<200 workspaces/reports): no impact
- Medium tenants (200–1000): requires 2–5 runs
- Large tenants (1000+): requires multiple sessions over several hours

**Implemented solution:**
- Automatic checkpoint system
- Collection can be resumed across multiple runs
- Scripts stop upon detecting rate limit (fail fast)

**Time estimates:**
| Item count | Total time | Runs needed |
|------------|------------|-------------|
| 100 items | ~5 min | 1 |
| 200 items | ~10 min | 1 |
| 500 items | ~1h (with pauses) | 3 |
| 1000 items | ~3–5h (with pauses) | 5–7 |
| 2000 items | ~8–12h (with pauses) | 10–15 |

---

### Personal Workspaces

**Problem:**
Personal Workspaces (format: `"PersonalWorkspace Name (email)"`) **do not support** the following Admin APIs:
- `GET /admin/groups/{groupId}/users`
- `GET /admin/reports/{reportId}/users`

**Observed behavior:**
- Return `404 Not Found` when attempting to fetch users
- In some cases, return `429 Too Many Requests` (consuming rate limit unnecessarily)

**Implemented solution:**
- WorkspaceAccessCollector **automatically filters** Personal Workspaces before making API calls
- ReportAccessCollector **automatically filters** reports inside Personal Workspaces
- Dramatically reduces unnecessary requests

**Impact on corporate tenants:**
- Typical tenants have 30–60% Personal Workspaces
- Example: 302 total workspaces → 186 Personal (62%) → only 116 need to be collected

---

### Admin Scan API — WorkspaceInventoryCollector

**Batching limit:** 100 workspaces per scan request

**Processing time:**
- Each scan takes ~5–10 seconds
- Large tenants (500+ workspaces) require multiple sequential scans

**Data limitations:**
- The scan returns a **snapshot** at a point in time, not real-time data
- Data may be slightly stale (seconds/minutes)
- Scans do not return historical data or time-series metrics

**Fields not returned by the scan:**
- Dataset refresh history
- Detailed capacity consumption
- Audit logs
- Executed queries

---

## 🔒 Permission Limitations

### Service Principal

**Required permissions:**
- **Tenant.Read.All** (Application permission)
- **Workspace.ReadWrite.All** (Application permission)
- Service Principal must be in the **Fabric Administrators** group

**What a Service Principal CANNOT do:**
- Access workspaces/reports without explicit permission (even as Admin)
- View dataset content (data, queries)
- Execute DAX queries directly on datasets (requires user context)
- Access APIs requiring delegated permissions (user context)

**Note on Admin APIs:**
- Admin APIs allow **listing** and **inspecting** resources
- They do NOT allow **executing** or **modifying** dataset/report content

---

### Device Flow

**Requirements:**
- The authenticating user must have the **Fabric Administrator** role in the tenant
- MFA is supported automatically
- Requires human interaction (cannot be automated)

**Limitations:**
- Token expires in ~1 hour
- Token cache is local (does not persist across machines)
- Not recommended for CI/CD or automation

---

## 💾 Checkpoint Limitations

### Data size

**Checkpoint stores:**
- List of processed IDs
- Partial data collected up to that point

**Potential issue in very large tenants:**
- Checkpoint files can grow to several MB
- Example: 5,000 reports with 10 accesses each = ~50MB checkpoint
- Loading/saving checkpoint may take a few seconds

**Mitigation:**
- Checkpoint stores only IDs and partial data, it does not duplicate the inventory
- Compact JSON format

---

### Checkpoint invalidation

**Checkpoint becomes invalid if:**
- You re-run the inventory collection (new IDs are generated)
- Workspaces/reports are deleted between runs
- The structure of `inventory_result` changes

**Symptoms:**
- Checkpoint is detected but no items are skipped
- Collection processes items that appear duplicated

**Solution:**
- Manually delete the checkpoint: `rm output/checkpoint_*.json`
- Re-run the collection from scratch

---

## 📊 Performance Limitations

### Inventory (WorkspaceInventoryCollector)

**Expected performance:**
- ~100 workspaces: 5–10 seconds
- ~500 workspaces: 30–60 seconds
- ~1,000 workspaces: 1–2 minutes

**Main bottleneck:** API scan time (not controllable)

---

### Access Collectors

**Expected performance (WITH checkpoint):**
- ~200 items: 3–5 minutes
- ~500 items: ~1h (with rate limit pauses)
- ~1,000 items: ~3–5h (with pauses)

**Expected performance (WITHOUT checkpoint):**
- Not feasible for >200 items (terminal blocked for hours)

---

### Export (FileExporter)

**Expected performance:**
- JSON: fast up to 100MB
- CSV: may be slow with large datasets (object flattening overhead)

**CSV limitations:**
- Nested arrays become JSON strings (requires manual parsing)
- Deeply nested objects generate long column names
- Excel has a ~1M row limit

---

## 🚫 Unsupported Features

### Consumption metrics collection

**Not implemented (out of scope):**
- CU consumption per workspace/dataset
- Executed queries and query performance

**Reason:**
- Requires access to the Capacity Metrics App dataset via DAX
- fabricgov focuses on governance (permissions, inventory, refresh) — not performance monitoring

---

### Resource modification

**fabricgov is READ-ONLY:**
- Does not modify workspaces, reports, or datasets
- Does not create, delete, or change permissions
- Does not execute refreshes or queries

**Reason:** focused on governance and assessment, not operational automation

---

### Real-time collection

**Limitations:**
- All data represents point-in-time snapshots
- No streaming or WebSockets
- No real-time change detection

**Unsupported use cases:**
- Continuous monitoring
- Real-time alerts
- Live dashboards

---

### Multi-tenancy

**Current limitation:**
- Collects one tenant at a time
- No support for aggregating data from multiple tenants
- Service Principal is tenant-specific

**Workaround:**
- Run collection separately for each tenant
- Aggregate results manually after export

---

## 🐛 Known Issues

### Issue #1: Checkpoint not detected after a long timeout

**Scenario:**
- Checkpoint saved
- Wait >24 hours
- Next run does not detect the checkpoint

**Cause:** `inventory_result.json` may be outdated

**Solution:**
- Re-run inventory collection
- Delete old checkpoints before resuming

---

### Issue #2: Special characters in workspace/report names

**Scenario:**
- Workspaces/reports with emojis or rare unicode characters
- CSV may not render correctly in Excel

**Solution:**
- Use JSON format instead of CSV
- Or import the CSV with explicit UTF-8 encoding

---

### Issue #3: Service Principal without permissions returns a generic error

**Scenario:**
- SP is not in the Fabric Administrators group
- Error returned: `403 Forbidden` with a generic message

**Solution:**
- Validate permissions following [docs/en/authentication.md](authentication.md)
- Wait up to 15 minutes after adding to the group (permission propagation)

---

## 📝 Microsoft-Documented Limitations

### Admin APIs may change without notice

**Microsoft does not guarantee:**
- Stability of Admin APIs (may change at any time)
- Backward compatibility for schema changes
- SLA availability for Admin APIs

**Impact:**
- fabricgov may break after Microsoft updates
- Always test in a non-production environment first

---

### Dynamic throttling

**Microsoft may dynamically adjust limits:**
- Rate limits may vary by tenant
- Peak hours may have more aggressive limits
- Tenants with a history of abuse may have reduced limits

**Impact:**
- Checkpoint timing may vary between runs
- 1h30min pauses may not be sufficient in some cases

---

## 🔮 Planned Limitation Removals

### v0.7.0
- Automatically generated HTML report from collected data

### v0.8.0
- `fabricgov analyze` — automatic governance findings (datasets without owners, external users, workspaces without refresh)

### v0.9.0
- Azure Key Vault integration for credential management
- `fabricgov diff` — comparison between snapshots from different collection runs

### v1.0.0
- Full documentation via MkDocs

---

## 💡 Workarounds and Solutions

### For very large tenants (2000+ items)

**Option 1: Scheduled collection**
- Configure a cron job or Task Scheduler
- Run overnight
- Results available in the morning

**Option 2: Distributed collection**
- Use multiple Service Principals (not officially documented/supported)
- Each SP collects a subset of workspaces
- Aggregate results manually

---

## 📞 Reporting Limitations

If you find an undocumented limitation:

1. Check whether it is already listed in this document
2. Open an [Issue on GitHub](https://github.com/luhborba/fabricgov/issues)
3. Include:
   - Description of the limitation
   - Environment (tenant size, collection type)
   - Full output/error
   - Steps to reproduce

---

**[← Back to README](../../README.md)**
