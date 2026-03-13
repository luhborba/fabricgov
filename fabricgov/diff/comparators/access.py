"""Comparador de permissões de acesso entre dois snapshots."""
from __future__ import annotations

from fabricgov.diff.snapshot import Snapshot

_ACCESS_FILES = [
    ("workspace_access", "workspace_id", "workspace_name"),
    ("report_access", "report_id", "report_name"),
    ("dataset_access", "dataset_id", "dataset_name"),
    ("dataflow_access", "dataflow_id", "dataflow_name"),
]


def compare(snap_from: Snapshot, snap_to: Snapshot) -> dict:
    from_map = _load_access(snap_from)
    to_map = _load_access(snap_to)

    if not from_map and not to_map:
        return {"available": False, "granted": [], "revoked": [], "role_changed": []}

    from_keys = set(from_map)
    to_keys = set(to_map)

    granted = [from_map[k] if k in from_map else to_map[k] for k in to_keys - from_keys]
    granted = [to_map[k] for k in to_keys - from_keys]
    revoked = [from_map[k] for k in from_keys - to_keys]

    # Detecta mudança de papel: mesma identidade (source, resource, user) com role diferente
    from_by_id = _group_by_identity(from_map)
    to_by_id = _group_by_identity(to_map)

    role_changed = []
    for identity in set(from_by_id) & set(to_by_id):
        roles_before = from_by_id[identity]
        roles_after = to_by_id[identity]
        if roles_before != roles_after:
            source, resource_id, resource_name, user_email = identity
            role_changed.append({
                "source": source,
                "resource_id": resource_id,
                "resource_name": resource_name,
                "user_email": user_email,
                "role_before": sorted(roles_before),
                "role_after": sorted(roles_after),
            })

    return {
        "available": True,
        "granted": granted,
        "revoked": revoked,
        "role_changed": role_changed,
    }


def _load_access(snap: Snapshot) -> dict[tuple, dict]:
    """Retorna dict keyed por (source, resource_id, user_email, role)."""
    result: dict[tuple, dict] = {}
    for fname, id_col, name_col in _ACCESS_FILES:
        df = snap.read_csv(fname)
        if df is None or df.empty:
            continue

        user_col = "user_email" if "user_email" in df.columns else None
        role_col = "role" if "role" in df.columns else ("permission" if "permission" in df.columns else None)

        if not user_col:
            continue

        for _, row in df.iterrows():
            user = str(row.get(user_col, "")).strip()
            if not user:
                continue
            resource_id = str(row.get(id_col, "")).strip() if id_col in df.columns else ""
            resource_name = str(row.get(name_col, "")).strip() if name_col in df.columns else resource_id
            role = str(row.get(role_col, "")).strip() if role_col else ""

            key = (fname, resource_id, user, role)
            result[key] = {
                "source": fname,
                "resource_id": resource_id,
                "resource_name": resource_name,
                "user_email": user,
                "role": role,
            }
    return result


def _group_by_identity(access_map: dict[tuple, dict]) -> dict[tuple, frozenset]:
    """Agrupa por (source, resource_id, resource_name, user_email) → frozenset de roles."""
    result: dict[tuple, set] = {}
    for (source, resource_id, user, role), entry in access_map.items():
        identity = (source, resource_id, entry.get("resource_name", resource_id), user)
        result.setdefault(identity, set()).add(role)
    return {k: frozenset(v) for k, v in result.items()}
