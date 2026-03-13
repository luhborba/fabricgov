"""Comparador de workspaces entre dois snapshots."""
from __future__ import annotations

from fabricgov.diff.snapshot import Snapshot


def compare(snap_from: Snapshot, snap_to: Snapshot) -> dict:
    df_from = snap_from.read_csv("workspaces")
    df_to = snap_to.read_csv("workspaces")

    if df_from is None and df_to is None:
        return {"available": False, "added": [], "removed": [], "changed": []}

    from_map = _to_map(df_from)
    to_map = _to_map(df_to)

    from_ids = set(from_map)
    to_ids = set(to_map)

    added = [_ws_dict(to_map[i]) for i in sorted(to_ids - from_ids)]
    removed = [_ws_dict(from_map[i]) for i in sorted(from_ids - to_ids)]

    changed = []
    for ws_id in sorted(from_ids & to_ids):
        changes = _detect_changes(from_map[ws_id], to_map[ws_id])
        if changes:
            changed.append({
                "id": ws_id,
                "name": str(to_map[ws_id].get("name", ws_id)),
                "changes": changes,
            })

    return {
        "available": True,
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def _to_map(df) -> dict[str, dict]:
    if df is None or df.empty or "id" not in df.columns:
        return {}
    return {str(row["id"]): dict(row) for _, row in df.iterrows()}


def _ws_dict(row: dict) -> dict:
    return {
        "id": str(row.get("id", "")),
        "name": str(row.get("name", "")),
        "type": str(row.get("type", "")),
        "state": str(row.get("state", "")),
        "isOnDedicatedCapacity": str(row.get("isOnDedicatedCapacity", "")),
        "capacityId": str(row.get("capacityId", "")),
    }


def _detect_changes(row_from: dict, row_to: dict) -> list[str]:
    changes = []
    checks = [
        ("name", "nome"),
        ("type", "tipo"),
        ("state", "estado"),
        ("isOnDedicatedCapacity", "capacidade dedicada"),
        ("capacityId", "capacidade"),
    ]
    for col, label in checks:
        v_from = str(row_from.get(col, "")).strip()
        v_to = str(row_to.get(col, "")).strip()
        if v_from != v_to:
            changes.append(f"{label}: '{v_from}' → '{v_to}'")
    return changes
