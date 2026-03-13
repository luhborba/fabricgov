"""Comparador de artefatos entre dois snapshots."""
from __future__ import annotations

from fabricgov.diff.snapshot import Snapshot


def compare(snap_from: Snapshot, snap_to: Snapshot) -> dict:
    from_arts = snap_from.artifact_csvs()
    to_arts = snap_to.artifact_csvs()

    if not from_arts and not to_arts:
        return {"available": False, "added": [], "removed": []}

    all_types = sorted(set(from_arts) | set(to_arts))
    added: list[dict] = []
    removed: list[dict] = []

    for artifact_type in all_types:
        df_f = from_arts.get(artifact_type)
        df_t = to_arts.get(artifact_type)

        from_set = _artifact_set(df_f)
        to_set = _artifact_set(df_t)

        for ws_id, art_id, name in sorted(to_set - from_set):
            added.append({"type": artifact_type, "workspace_id": ws_id, "artifact_id": art_id, "name": name})

        for ws_id, art_id, name in sorted(from_set - to_set):
            removed.append({"type": artifact_type, "workspace_id": ws_id, "artifact_id": art_id, "name": name})

    return {
        "available": True,
        "added": added,
        "removed": removed,
    }


def _artifact_set(df) -> set[tuple[str, str, str]]:
    if df is None or df.empty:
        return set()
    result: set[tuple[str, str, str]] = set()
    for _, row in df.iterrows():
        ws_id = str(row.get("workspace_id", "")).strip()
        art_id = str(row.get("id", "")).strip()
        name = str(row.get("name", "")).strip()
        if ws_id and name:
            result.add((ws_id, art_id, name))
    return result
