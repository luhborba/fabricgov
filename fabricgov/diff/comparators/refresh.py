"""Comparador de refresh (schedules + health) entre dois snapshots."""
from __future__ import annotations

from fabricgov.diff.snapshot import Snapshot


def compare(snap_from: Snapshot, snap_to: Snapshot) -> dict:
    result: dict = {}
    result.update(_compare_schedules(snap_from, snap_to))
    result.update(_compare_health(snap_from, snap_to))
    return result


def _compare_schedules(snap_from: Snapshot, snap_to: Snapshot) -> dict:
    df_f = snap_from.read_csv("refresh_schedules")
    df_t = snap_to.read_csv("refresh_schedules")

    if df_f is None and df_t is None:
        return {"schedules_available": False, "schedules_added": [], "schedules_removed": []}

    from_set = _schedule_set(df_f)
    to_set = _schedule_set(df_t)

    return {
        "schedules_available": True,
        "schedules_added": [
            {"dataset_id": s[0], "dataset_name": s[1]}
            for s in sorted(to_set - from_set)
        ],
        "schedules_removed": [
            {"dataset_id": s[0], "dataset_name": s[1]}
            for s in sorted(from_set - to_set)
        ],
    }


def _schedule_set(df) -> set[tuple[str, str]]:
    if df is None or df.empty:
        return set()
    result: set[tuple[str, str]] = set()
    for _, row in df.iterrows():
        ds_id = str(row.get("dataset_id", "")).strip()
        ds_name = str(row.get("dataset_name", row.get("name", ""))).strip()
        if ds_id:
            result.add((ds_id, ds_name))
    return result


def _compare_health(snap_from: Snapshot, snap_to: Snapshot) -> dict:
    df_f = snap_from.read_csv("refresh_history")
    df_t = snap_to.read_csv("refresh_history")

    if df_f is None and df_t is None:
        return {"health_available": False, "degraded": [], "improved": []}

    from_stats = _failure_stats(df_f)
    to_stats = _failure_stats(df_t)

    all_datasets = set(from_stats) | set(to_stats)
    degraded: list[dict] = []
    improved: list[dict] = []

    for ds_id in sorted(all_datasets):
        f_before = from_stats.get(ds_id, {}).get("failures", 0)
        f_after = to_stats.get(ds_id, {}).get("failures", 0)
        name = (to_stats.get(ds_id) or from_stats.get(ds_id, {})).get("name", ds_id)
        ws = (to_stats.get(ds_id) or from_stats.get(ds_id, {})).get("workspace", "")

        if f_after > f_before:
            degraded.append({
                "dataset_id": ds_id,
                "name": name,
                "workspace": ws,
                "failures_before": f_before,
                "failures_after": f_after,
            })
        elif f_after < f_before:
            improved.append({
                "dataset_id": ds_id,
                "name": name,
                "workspace": ws,
                "failures_before": f_before,
                "failures_after": f_after,
            })

    return {
        "health_available": True,
        "degraded": sorted(degraded, key=lambda x: x["failures_after"] - x["failures_before"], reverse=True),
        "improved": improved,
    }


def _failure_stats(df) -> dict[str, dict]:
    if df is None or df.empty:
        return {}

    id_col = next((c for c in ["dataset_id", "artifact_id"] if c in df.columns), None)
    name_col = "artifact_name" if "artifact_name" in df.columns else None
    ws_col = "workspace_name" if "workspace_name" in df.columns else None
    status_col = "status" if "status" in df.columns else None

    if not id_col or not status_col:
        return {}

    result: dict[str, dict] = {}
    for ds_id, group in df.groupby(id_col):
        ds_id_str = str(ds_id)
        failures = int(group[status_col].str.lower().isin(["failed", "error"]).sum())
        name = str(group[name_col].iloc[0]) if name_col else ds_id_str
        ws = str(group[ws_col].iloc[0]) if ws_col else ""
        result[ds_id_str] = {"name": name, "workspace": ws, "failures": failures}

    return result
