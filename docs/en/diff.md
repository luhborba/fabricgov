# fabricgov diff — Snapshot Comparison

The `fabricgov diff` command compares two fabricgov output snapshots and generates a `diff.json` file containing all differences found between the two points in time.

> `diff.json` is designed to be consumed in the future by `fabricgov report`, adding comparison sections to the HTML report.

---

## What is compared?

| Dimension | What is detected |
|-----------|-----------------|
| **Workspaces** | Added, removed, and changed (name, type, state, capacity) |
| **Artifacts** | Reports, datasets, dataflows, lakehouses and others added or removed per workspace |
| **Access** | Permissions granted, revoked, and roles changed (4 sources: workspace, report, dataset, dataflow) |
| **Refresh (schedules)** | Schedules added or removed |
| **Refresh (health)** | Datasets degraded (more failures) or improved (fewer failures) |
| **Findings** | New findings, resolved findings, and findings with changed counts |

---

## Basic usage

```bash
# Automatically compares the 2 most recent runs in output/
fabricgov diff

# Explicit snapshots
fabricgov diff --from output/20260301_120000 --to output/20260309_143000

# Save diff to a different location
fabricgov diff --output ~/reports/diff.json
```

---

## Available options

| Option | Default | Description |
|--------|---------|-------------|
| `--from PATH` | second-to-last run | Base snapshot (the older one) |
| `--to PATH` | latest run | Current snapshot (the newer one) |
| `--output-dir DIR` | `output` | Root directory to search for automatic runs |
| `--output FILE` | `<to>/diff.json` | Path of the generated diff.json file |

---

## Terminal output

Displays an executive summary with totals per section:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  fabricgov diff — Executive Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Interval: 8 days between snapshots

  Workspaces    +3 added  -1 removed  ~2 changed
  Artifacts     +12 added  -2 removed
  Access        +5 granted  -2 revoked  ~1 role changed
  Refresh       ↓ 2 degraded  ↑ 1 improved
  Findings      ⚠ 1 new  ✓ 2 resolved

✅ diff.json saved to: output/20260309_143000/diff.json
```

---

## diff.json structure

```json
{
  "meta": {
    "snapshot_from": "output/20260301_120000",
    "snapshot_to":   "output/20260309_143000",
    "from_ts": "2026-03-01T12:00:00",
    "to_ts":   "2026-03-09T14:30:00",
    "days_between": 8,
    "generated_at": "2026-03-13T10:00:00"
  },
  "workspaces": {
    "available": true,
    "added":   [{"id": "...", "name": "New Workspace", "type": "Workspace", ...}],
    "removed": [...],
    "changed": [{"id": "...", "name": "...", "changes": ["state: 'Active' → 'Inactive'"]}]
  },
  "artifacts": {
    "available": true,
    "added":   [{"type": "reports", "workspace_id": "...", "artifact_id": "...", "name": "Sales KPI"}],
    "removed": [...]
  },
  "access": {
    "available": true,
    "granted":      [{"source": "workspace_access", "resource_name": "...", "user_email": "...", "role": "Admin"}],
    "revoked":      [...],
    "role_changed": [{"source": "...", "resource_name": "...", "user_email": "...", "role_before": ["Member"], "role_after": ["Admin"]}]
  },
  "refresh": {
    "schedules_available": true,
    "schedules_added":   [{"dataset_id": "...", "dataset_name": "..."}],
    "schedules_removed": [...],
    "health_available": true,
    "degraded": [{"name": "Sales Data", "workspace": "Marketing", "failures_before": 0, "failures_after": 3}],
    "improved": [...]
  },
  "findings": {
    "new":           [...],
    "resolved":      [...],
    "count_changed": [{"severity": "HIGH", "message": "...", "count_before": 2, "count_after": 5, "delta": 3}]
  },
  "summary": {
    "workspaces_added": 3,
    "workspaces_removed": 1,
    "workspaces_changed": 2,
    "artifacts_added": 12,
    "artifacts_removed": 2,
    "access_granted": 5,
    "access_revoked": 2,
    "access_role_changed": 1,
    "schedules_added": 1,
    "schedules_removed": 0,
    "datasets_degraded": 2,
    "datasets_improved": 1,
    "findings_new": 1,
    "findings_resolved": 2,
    "findings_count_changed": 1
  }
}
```

---

## Data dependencies per section

| Section | Required CSV files |
|---------|--------------------|
| `workspaces` | `workspaces.csv` |
| `artifacts` | All artifact CSVs (reports, datasets, lakehouses, etc.) |
| `access` | `workspace_access.csv`, `report_access.csv`, `dataset_access.csv`, `dataflow_access.csv` |
| `refresh.schedules` | `refresh_schedules.csv` |
| `refresh.health` | `refresh_history.csv` |
| `findings` | All available data (runs InsightsEngine on each snapshot) |

If a file does not exist in one or both snapshots, the corresponding section is marked `"available": false` and lists are empty — no error is raised.

---

## Usage as a Python library

```python
from fabricgov.diff import DiffEngine, Snapshot, find_run_dirs

# Auto-detect the 2 most recent runs
runs = find_run_dirs("output")
snap_from = Snapshot(runs[-2])
snap_to   = Snapshot(runs[-1])

engine = DiffEngine(snap_from, snap_to)
result = engine.run()

# Access the summary
print(result.summary)

# Save diff.json
from pathlib import Path
result.save(Path("output/diff.json"))

# Or convert to dict (for integration with other systems)
diff_dict = result.to_dict()
```

---

## Use cases

### Weekly access audit

```python
from fabricgov.diff import DiffEngine, Snapshot, find_run_dirs

runs = find_run_dirs("output")
result = DiffEngine(Snapshot(runs[-2]), Snapshot(runs[-1])).run()

for entry in result.access["granted"]:
    if "#EXT#" in entry.get("user_email", ""):
        print(f"⚠ External access granted: {entry['user_email']} on {entry['resource_name']}")
```

### Detect refresh degradation

```python
for ds in result.refresh.get("degraded", []):
    print(f"↓ {ds['name']} ({ds['workspace']}): {ds['failures_before']} → {ds['failures_after']} failures")
```

### Check tenant growth

```python
s = result.summary
print(f"Workspaces: {'+' if s['workspaces_added'] >= s['workspaces_removed'] else ''}{s['workspaces_added'] - s['workspaces_removed']}")
print(f"Artifacts:  {'+' if s['artifacts_added'] >= s['artifacts_removed'] else ''}{s['artifacts_added'] - s['artifacts_removed']}")
```

---

## Common errors

| Error | Cause | Solution |
|-------|-------|---------|
| `At least 2 output folders required` | Fewer than 2 runs in `output/` | Run `fabricgov collect all` twice, or use explicit `--from`/`--to` |
| `Folder not found` | Provided path does not exist | Check the path with `ls output/` |
| Section with `"available": false` | CSV not present in snapshot | Run the corresponding collector before generating the diff |

---

**[← Back: Findings Analysis](report.md)** | **[Next: Authentication →](authentication.md)**
