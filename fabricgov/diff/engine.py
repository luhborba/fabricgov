"""
DiffEngine: orquestra todos os comparators e produz um DiffResult.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from fabricgov.diff.snapshot import Snapshot
from fabricgov.diff.comparators import access, artifacts, findings, refresh, workspace


@dataclass
class DiffResult:
    meta: dict = field(default_factory=dict)
    workspaces: dict = field(default_factory=dict)
    artifacts: dict = field(default_factory=dict)
    access: dict = field(default_factory=dict)
    refresh: dict = field(default_factory=dict)
    findings: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )


class DiffEngine:
    def __init__(self, snap_from: Snapshot, snap_to: Snapshot):
        self.snap_from = snap_from
        self.snap_to = snap_to

    def run(self) -> DiffResult:
        ws_diff = workspace.compare(self.snap_from, self.snap_to)
        art_diff = artifacts.compare(self.snap_from, self.snap_to)
        acc_diff = access.compare(self.snap_from, self.snap_to)
        ref_diff = refresh.compare(self.snap_from, self.snap_to)
        find_diff = findings.compare(self.snap_from, self.snap_to)

        days = (self.snap_to.ts - self.snap_from.ts).days

        return DiffResult(
            meta={
                "snapshot_from": str(self.snap_from.path),
                "snapshot_to": str(self.snap_to.path),
                "from_ts": self.snap_from.ts.isoformat(),
                "to_ts": self.snap_to.ts.isoformat(),
                "days_between": days,
                "generated_at": datetime.now().isoformat(),
            },
            workspaces=ws_diff,
            artifacts=art_diff,
            access=acc_diff,
            refresh=ref_diff,
            findings=find_diff,
            summary={
                "workspaces_added": len(ws_diff.get("added", [])),
                "workspaces_removed": len(ws_diff.get("removed", [])),
                "workspaces_changed": len(ws_diff.get("changed", [])),
                "artifacts_added": len(art_diff.get("added", [])),
                "artifacts_removed": len(art_diff.get("removed", [])),
                "access_granted": len(acc_diff.get("granted", [])),
                "access_revoked": len(acc_diff.get("revoked", [])),
                "access_role_changed": len(acc_diff.get("role_changed", [])),
                "schedules_added": len(ref_diff.get("schedules_added", [])),
                "schedules_removed": len(ref_diff.get("schedules_removed", [])),
                "datasets_degraded": len(ref_diff.get("degraded", [])),
                "datasets_improved": len(ref_diff.get("improved", [])),
                "findings_new": len(find_diff.get("new", [])),
                "findings_resolved": len(find_diff.get("resolved", [])),
                "findings_count_changed": len(find_diff.get("count_changed", [])),
            },
        )
