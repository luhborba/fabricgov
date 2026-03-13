"""
Snapshot: representa uma pasta de output do fabricgov (YYYYMMDD_HHMMSS).
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

import pandas as pd

_RUN_DIR_PATTERN = re.compile(r"^\d{8}_\d{6}$")

_SYSTEM_CSVS = {
    "workspaces", "workspace_access", "report_access", "dataset_access",
    "dataflow_access", "refresh_history", "refresh_schedules", "domains",
    "tags", "capacities", "workloads", "summary", "activity_events",
    "workspace_access_errors", "report_access_errors", "dataset_access_errors",
    "dataflow_access_errors", "refresh_history_errors", "workloads_errors",
}


def find_run_dirs(output_dir: str | Path) -> list[Path]:
    """Retorna lista de run dirs ordenada do mais antigo para o mais recente."""
    base = Path(output_dir)
    if not base.exists():
        return []
    candidates = [
        d for d in base.iterdir()
        if d.is_dir() and _RUN_DIR_PATTERN.match(d.name)
    ]
    return sorted(candidates, key=lambda d: d.name)


class Snapshot:
    """Representa um snapshot de output do fabricgov."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.name = self.path.name
        self.ts = datetime.strptime(self.path.name, "%Y%m%d_%H%M%S")

    def read_csv(self, name: str) -> pd.DataFrame | None:
        p = self.path / f"{name}.csv"
        if not p.exists():
            return None
        try:
            return pd.read_csv(p, low_memory=False)
        except Exception:
            return None

    def artifact_csvs(self) -> dict[str, pd.DataFrame]:
        """Retorna todos os CSVs de artefatos (exclui arquivos de sistema)."""
        result: dict[str, pd.DataFrame] = {}
        for p in sorted(self.path.glob("*.csv")):
            if p.stem in _SYSTEM_CSVS:
                continue
            df = self.read_csv(p.stem)
            if df is not None and not df.empty:
                result[p.stem] = df
        return result
