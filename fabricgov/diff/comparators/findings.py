"""Comparador de findings de governança entre dois snapshots."""
from __future__ import annotations

from fabricgov.diff.snapshot import Snapshot


def compare(snap_from: Snapshot, snap_to: Snapshot) -> dict:
    findings_from = _get_findings(snap_from)
    findings_to = _get_findings(snap_to)

    # Chave por (severity, message) — identifica o mesmo tipo de finding
    from_map = {f"{f['severity']}||{f['message']}": f for f in findings_from}
    to_map = {f"{f['severity']}||{f['message']}": f for f in findings_to}

    new_findings = [to_map[k] for k in set(to_map) - set(from_map)]
    resolved = [from_map[k] for k in set(from_map) - set(to_map)]

    count_changed = []
    for k in set(from_map) & set(to_map):
        c_before = from_map[k].get("count", 0)
        c_after = to_map[k].get("count", 0)
        if c_before != c_after:
            count_changed.append({
                "severity": to_map[k]["severity"],
                "message": to_map[k]["message"],
                "count_before": c_before,
                "count_after": c_after,
                "delta": c_after - c_before,
            })

    return {
        "new": new_findings,
        "resolved": resolved,
        "count_changed": sorted(count_changed, key=lambda x: abs(x["delta"]), reverse=True),
    }


def _get_findings(snap: Snapshot) -> list[dict]:
    try:
        from fabricgov.reporters.insights import InsightsEngine
        engine = InsightsEngine(snap.path)
        ins = engine.compute()
        return [f for f in ins.findings if f.get("severity") != "OK"]
    except Exception:
        return []
