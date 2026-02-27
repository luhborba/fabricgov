"""
InsightsEngine: lê os arquivos de output do fabricgov e computa todas as métricas
necessárias para o relatório HTML.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd


# ---------------------------------------------------------------------------
# Dataclass de resultado
# ---------------------------------------------------------------------------

@dataclass
class ReportInsights:
    # --- Metadados ---
    source_folder: str
    generated_at: str

    # --- Flags de disponibilidade ---
    has_workspace_data: bool = False
    has_access_data: bool = False
    has_refresh_data: bool = False
    has_infra_data: bool = False
    has_domain_data: bool = False

    # --- KPIs ---
    total_workspaces: int = 0
    total_artifacts: int = 0
    artifacts_by_type: dict[str, int] = field(default_factory=dict)
    total_users: int = 0
    external_users_count: int = 0
    datasets_without_owner: int = 0
    refresh_success_rate: float | None = None
    workspaces_on_dedicated: int = 0
    workspaces_on_shared: int = 0

    # --- Dados para gráficos ---
    workspace_type_counts: dict[str, int] = field(default_factory=dict)
    top_workspaces: list[dict] = field(default_factory=list)
    role_distribution: dict[str, int] = field(default_factory=dict)
    principal_type_dist: dict[str, int] = field(default_factory=dict)
    refresh_status_counts: dict[str, int] = field(default_factory=dict)
    refresh_timeline: list[dict] = field(default_factory=list)
    capacity_workspace_counts: dict[str, int] = field(default_factory=dict)
    workload_state_counts: dict[str, int] = field(default_factory=dict)
    sku_counts: dict[str, int] = field(default_factory=dict)

    # --- Tabelas ---
    workspace_rows: list[dict] = field(default_factory=list)
    external_users: list[dict] = field(default_factory=list)
    failed_refreshes: list[dict] = field(default_factory=list)
    stale_datasets: list[dict] = field(default_factory=list)
    single_user_workspaces: list[dict] = field(default_factory=list)
    top_users_by_access: list[dict] = field(default_factory=list)
    capacities_list: list[dict] = field(default_factory=list)
    domains_list: list[dict] = field(default_factory=list)

    # --- Findings de governança ---
    findings: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class InsightsEngine:
    """Lê os arquivos de uma pasta de output e computa todas as métricas."""

    ARTIFACT_FILES = [
        "reports", "datasets", "dataflows", "dashboards", "datamarts",
        "lakehouses", "warehouses", "notebooks", "datasourceInstances",
        "paginatedReports", "dataflows", "Eventstream", "Eventhouse",
        "KQLDatabase", "KQLDashboard", "Reflex", "DataPipeline",
        "MirroredDatabase", "SQLAnalyticsEndpoint",
    ]

    def __init__(self, source_dir: str | Path):
        self.src = Path(source_dir)

    def _read_csv(self, name: str) -> pd.DataFrame | None:
        path = self.src / f"{name}.csv"
        if not path.exists():
            return None
        try:
            return pd.read_csv(path, low_memory=False)
        except Exception:
            return None

    def _read_json(self, name: str) -> dict | list | None:
        path = self.src / f"{name}.json"
        if not path.exists():
            return None
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def compute(self) -> ReportInsights:
        ins = ReportInsights(
            source_folder=str(self.src),
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        self._load_summary(ins)
        self._load_workspaces(ins)
        self._load_access(ins)
        self._load_refresh(ins)
        self._load_infra(ins)
        self._load_domains(ins)
        self._build_findings(ins)

        return ins

    # ------------------------------------------------------------------

    def _load_summary(self, ins: ReportInsights) -> None:
        """Lê summary.json — tenta múltiplos formatos (inventário, refresh, acesso)."""
        summary = self._read_json("summary")
        if summary and isinstance(summary, dict):
            # Formato do inventário
            if "total_workspaces" in summary:
                ins.total_workspaces = summary["total_workspaces"]
            if "total_items" in summary:
                ins.total_artifacts = summary["total_items"]
            if "items_by_type" in summary:
                # Filtra tipos com count > 0
                ins.artifacts_by_type = {
                    k: v for k, v in summary["items_by_type"].items() if v and int(v) > 0
                }

    def _load_workspaces(self, ins: ReportInsights) -> None:
        df = self._read_csv("workspaces")
        if df is None or df.empty:
            return
        ins.has_workspace_data = True

        # Fallback: conta workspaces diretamente do CSV
        if ins.total_workspaces == 0:
            ins.total_workspaces = len(df)

        # Tipo de workspace
        if "type" in df.columns:
            ins.workspace_type_counts = df["type"].value_counts().to_dict()

        # Dedicated vs Shared
        if "isOnDedicatedCapacity" in df.columns:
            dedicated = df["isOnDedicatedCapacity"].fillna("").astype(str).apply(
                lambda x: x.strip().lower() in ("true", "1", "yes")
            )
            ins.workspaces_on_dedicated = int(dedicated.sum())
            ins.workspaces_on_shared = int((~dedicated).sum())

        # Monta mapa id → nome
        names: dict[str, str] = {}
        if "id" in df.columns and "name" in df.columns:
            names = dict(zip(df["id"].astype(str), df["name"].astype(str)))

        # Conta artefatos por workspace lendo todos os arquivos de artefato
        counts: dict[str, int] = {}
        artifact_type_counts: dict[str, int] = {}  # para fallback de artifacts_by_type

        # Lista de todos os CSVs presentes na pasta (exceto os de acesso/refresh/infra)
        skip = {
            "workspaces", "workspace_access", "report_access", "dataset_access",
            "dataflow_access", "refresh_history", "refresh_schedules", "domains",
            "tags", "capacities", "workloads", "summary",
            "workspace_access_errors", "report_access_errors", "dataset_access_errors",
            "dataflow_access_errors", "refresh_history_errors", "workloads_errors",
        }
        for csv_path in self.src.glob("*.csv"):
            stem = csv_path.stem
            if stem in skip:
                continue
            adf = self._read_csv(stem)
            if adf is None or "workspace_id" not in adf.columns:
                continue
            cnt_total = len(adf)
            artifact_type_counts[stem] = artifact_type_counts.get(stem, 0) + cnt_total
            for ws_id, cnt in adf["workspace_id"].value_counts().items():
                counts[str(ws_id)] = counts.get(str(ws_id), 0) + int(cnt)

        # Fallback: preenche artifacts_by_type e total_artifacts a partir dos CSVs
        if not ins.artifacts_by_type and artifact_type_counts:
            ins.artifacts_by_type = artifact_type_counts
        if ins.total_artifacts == 0 and artifact_type_counts:
            ins.total_artifacts = sum(artifact_type_counts.values())

        # Top 10 workspaces por artefatos
        top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ins.top_workspaces = [
            {"name": names.get(ws_id, ws_id), "count": cnt}
            for ws_id, cnt in top
        ]

        # Tabela detalhada de workspaces (para seção dedicada)
        workspace_rows = []
        for _, row in df.iterrows():
            ws_id = str(row.get("id", ""))
            artifact_count = counts.get(ws_id, 0)
            is_ded = str(row.get("isOnDedicatedCapacity", "")).strip().lower() in ("true", "1", "yes")
            workspace_rows.append({
                "name": str(row.get("name", "—")),
                "type": str(row.get("type", "—")),
                "state": str(row.get("state", "—")),
                "dedicated": is_ded,
                "capacity_id": str(row.get("capacityId", "—")),
                "artifact_count": artifact_count,
            })
        workspace_rows.sort(key=lambda x: x["artifact_count"], reverse=True)
        ins.workspace_rows = workspace_rows

        # datasets_without_owner: via datasets.csv
        ddf = self._read_csv("datasets")
        if ddf is not None and "configuredBy" in ddf.columns:
            ins.datasets_without_owner = int(
                ddf["configuredBy"].isna().sum()
                + (ddf["configuredBy"].astype(str).str.strip() == "").sum()
            )

    def _load_access(self, ins: ReportInsights) -> None:
        access_files = [
            "workspace_access", "report_access",
            "dataset_access", "dataflow_access",
        ]
        all_emails: set[str] = set()
        ext_emails: dict[str, dict] = {}  # email → {roles, ws_count}

        role_dist: dict[str, int] = {}
        principal_dist: dict[str, int] = {}

        has_any = False
        for fname in access_files:
            df = self._read_csv(fname)
            if df is None or df.empty:
                continue
            has_any = True

            # Emails únicos
            if "user_email" in df.columns:
                emails = df["user_email"].fillna("").astype(str)
                all_emails.update(e for e in emails if e)

                # Externos
                ext_mask = emails.str.contains("#EXT#", na=False, case=False)
                for _, row in df[ext_mask].iterrows():
                    em = str(row.get("user_email", ""))
                    if em not in ext_emails:
                        ext_emails[em] = {"roles": set(), "workspace_count": 0}
                    role_col = row.get("role") or row.get("permission") or ""
                    if role_col:
                        ext_emails[em]["roles"].add(str(role_col))
                    ws = row.get("workspace_name") or row.get("workspace_id") or ""
                    if ws:
                        ext_emails[em]["workspace_count"] += 1

            # Roles (workspace_access)
            if fname == "workspace_access":
                if "role" in df.columns:
                    for role, cnt in df["role"].value_counts().items():
                        role_dist[str(role)] = role_dist.get(str(role), 0) + int(cnt)
                if "principal_type" in df.columns:
                    for pt, cnt in df["principal_type"].value_counts().items():
                        principal_dist[str(pt)] = principal_dist.get(str(pt), 0) + int(cnt)

                # Single-user workspaces
                if "workspace_id" in df.columns and "user_email" in df.columns:
                    ws_user_counts = df.groupby("workspace_id")["user_email"].nunique()
                    single = ws_user_counts[ws_user_counts == 1].index.tolist()
                    ws_names = {}
                    if "workspace_name" in df.columns:
                        ws_names = dict(zip(
                            df["workspace_id"].astype(str),
                            df["workspace_name"].astype(str),
                        ))
                    ins.single_user_workspaces = []
                    for ws_id in single[:20]:
                        sub = df[df["workspace_id"] == ws_id].iloc[0]
                        ins.single_user_workspaces.append({
                            "workspace": ws_names.get(str(ws_id), str(ws_id)),
                            "user_email": str(sub.get("user_email", "")),
                            "role": str(sub.get("role", "")),
                        })

        if not has_any:
            return

        ins.has_access_data = True
        ins.total_users = len(all_emails)
        ins.external_users_count = len(ext_emails)
        ins.role_distribution = role_dist
        ins.principal_type_dist = principal_dist

        ins.external_users = [
            {
                "email": em,
                "roles": ", ".join(sorted(info["roles"])) or "—",
                "workspace_count": info["workspace_count"],
            }
            for em, info in sorted(
                ext_emails.items(), key=lambda x: x[1]["workspace_count"], reverse=True
            )
        ][:50]

        # Top users por acesso
        wdf = self._read_csv("workspace_access")
        if wdf is not None and "user_email" in wdf.columns and "workspace_id" in wdf.columns:
            top_users = (
                wdf.groupby("user_email")["workspace_id"]
                .nunique()
                .sort_values(ascending=False)
                .head(10)
            )
            ins.top_users_by_access = [
                {"email": em, "workspace_count": int(cnt)}
                for em, cnt in top_users.items()
            ]

    def _load_refresh(self, ins: ReportInsights) -> None:
        df = self._read_csv("refresh_history")
        if df is None or df.empty:
            return
        ins.has_refresh_data = True

        # Status counts
        if "status" in df.columns:
            status_counts = df["status"].fillna("Unknown").value_counts().to_dict()
            ins.refresh_status_counts = {str(k): int(v) for k, v in status_counts.items()}

            total = len(df)
            completed = int(df["status"].str.lower().eq("completed").sum())
            ins.refresh_success_rate = round(completed / total * 100, 1) if total else None

        # Failed refreshes
        if "status" in df.columns:
            fail_mask = df["status"].str.lower().isin(["failed", "error", "disabled"])
            failed_df = df[fail_mask].copy()
            cols = ["artifact_name", "workspace_name", "start_time", "status", "service_exception_json"]
            available = [c for c in cols if c in failed_df.columns]
            ins.failed_refreshes = failed_df[available].head(50).to_dict("records")

        # Timeline (últimos 30 dias)
        if "start_time" in df.columns:
            try:
                df["_date"] = pd.to_datetime(df["start_time"], errors="coerce").dt.date
                cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).date()
                timeline = (
                    df[df["_date"] >= cutoff]
                    .groupby("_date")
                    .size()
                    .reset_index(name="count")
                )
                ins.refresh_timeline = [
                    {"date": str(row["_date"]), "count": int(row["count"])}
                    for _, row in timeline.iterrows()
                ]
            except Exception:
                pass

        # Stale datasets: sem refresh há 30+ dias
        if "start_time" in df.columns and "artifact_name" in df.columns:
            try:
                df["_dt"] = pd.to_datetime(df["start_time"], errors="coerce")
                latest = df.groupby("artifact_name")["_dt"].max().reset_index()
                cutoff_dt = datetime.now(timezone.utc) - timedelta(days=30)
                stale = latest[latest["_dt"] < cutoff_dt.replace(tzinfo=None)]
                if "workspace_name" in df.columns:
                    ws_map = dict(zip(df["artifact_name"], df["workspace_name"]))
                    stale = stale.copy()
                    stale["workspace"] = stale["artifact_name"].map(ws_map)
                ins.stale_datasets = [
                    {
                        "name": str(row["artifact_name"]),
                        "workspace": str(row.get("workspace", "—")),
                        "last_refresh": str(row["_dt"].date()) if pd.notna(row["_dt"]) else "Nunca",
                    }
                    for _, row in stale.head(50).iterrows()
                ]
            except Exception:
                pass

    def _load_infra(self, ins: ReportInsights) -> None:
        cap_df = self._read_csv("capacities")
        if cap_df is None or cap_df.empty:
            return
        ins.has_infra_data = True

        if "sku" in cap_df.columns:
            ins.sku_counts = cap_df["sku"].value_counts().to_dict()

        # Workspaces por capacidade (usando workspaces.csv)
        ws_df = self._read_csv("workspaces")
        if ws_df is not None and "capacityId" in ws_df.columns and "displayName" in cap_df.columns:
            cap_names = {}
            if "id" in cap_df.columns:
                cap_names = dict(zip(cap_df["id"].astype(str), cap_df["displayName"].astype(str)))
            ws_cap = ws_df["capacityId"].dropna().astype(str).value_counts()
            ins.capacity_workspace_counts = {
                cap_names.get(cid, cid): int(cnt)
                for cid, cnt in ws_cap.items()
            }

        # Lista de capacidades para tabela
        cols = [c for c in ["displayName", "sku", "state", "region"] if c in cap_df.columns]
        ins.capacities_list = cap_df[cols].head(50).to_dict("records")

        # Workloads
        wl_df = self._read_csv("workloads")
        if wl_df is not None and "state" in wl_df.columns:
            ins.workload_state_counts = wl_df["state"].value_counts().to_dict()

    def _load_domains(self, ins: ReportInsights) -> None:
        df = self._read_csv("domains")
        if df is None or df.empty:
            return
        ins.has_domain_data = True
        cols = [c for c in ["displayName", "description", "parentDomainId"] if c in df.columns]
        ins.domains_list = df[cols].head(100).to_dict("records")

    def _build_findings(self, ins: ReportInsights) -> None:
        findings = []

        if ins.datasets_without_owner > 0:
            ddf = self._read_csv("datasets")
            details: list[dict] = []
            if ddf is not None and "configuredBy" in ddf.columns:
                mask = ddf["configuredBy"].isna() | (ddf["configuredBy"].astype(str).str.strip() == "")
                for _, row in ddf[mask].head(100).iterrows():
                    details.append({
                        "name": str(row.get("name", "—")),
                        "workspace_name": str(row.get("workspace_name", "—")),
                        "id": str(row.get("id", "—")),
                    })
            findings.append({
                "severity": "CRITICAL",
                "badge": "danger",
                "icon": "🔴",
                "message": f"{ins.datasets_without_owner} dataset(s) sem owner definido (configuredBy vazio)",
                "message_en": f"{ins.datasets_without_owner} dataset(s) without defined owner (configuredBy empty)",
                "count": ins.datasets_without_owner,
                "details": details,
            })

        if ins.external_users_count > 0:
            findings.append({
                "severity": "HIGH",
                "badge": "warning",
                "icon": "🟠",
                "message": f"{ins.external_users_count} usuário(s) externo(s) (#EXT#) com acesso ao tenant",
                "message_en": f"{ins.external_users_count} external user(s) (#EXT#) with access to the tenant",
                "count": ins.external_users_count,
                "details": ins.external_users[:100],
            })

        failed_count = ins.refresh_status_counts.get("Failed", 0) + ins.refresh_status_counts.get("failed", 0)
        if failed_count > 0:
            findings.append({
                "severity": "HIGH",
                "badge": "warning",
                "icon": "🟠",
                "message": f"{failed_count} refresh(es) com falha no histórico coletado",
                "message_en": f"{failed_count} refresh(es) failed in the collected history",
                "count": failed_count,
                "details": ins.failed_refreshes[:100],
            })

        if len(ins.single_user_workspaces) > 0:
            findings.append({
                "severity": "MEDIUM",
                "badge": "info",
                "icon": "🔵",
                "message": f"{len(ins.single_user_workspaces)} workspace(s) com apenas 1 usuário (ponto único de falha)",
                "message_en": f"{len(ins.single_user_workspaces)} workspace(s) with only 1 user (single point of failure)",
                "count": len(ins.single_user_workspaces),
                "details": ins.single_user_workspaces,
            })

        if len(ins.stale_datasets) > 0:
            findings.append({
                "severity": "MEDIUM",
                "badge": "info",
                "icon": "🔵",
                "message": f"{len(ins.stale_datasets)} dataset(s) sem refresh nos últimos 30 dias",
                "message_en": f"{len(ins.stale_datasets)} dataset(s) without refresh in the last 30 days",
                "count": len(ins.stale_datasets),
                "details": ins.stale_datasets,
            })

        if not findings:
            findings.append({
                "severity": "OK",
                "badge": "success",
                "icon": "🟢",
                "message": "Nenhum finding crítico detectado com os dados disponíveis",
                "message_en": "No critical findings detected with the available data",
                "count": 0,
                "details": [],
            })

        ins.findings = findings
