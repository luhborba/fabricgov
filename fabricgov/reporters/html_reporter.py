"""
HtmlReporter: orquestra InsightsEngine + Plotly charts + Jinja2 template
para gerar um relatório HTML standalone.
Suporta PT e EN — generate_all() produz ambas as versões.
"""
from __future__ import annotations

from pathlib import Path

import plotly.graph_objects as go
from jinja2 import Environment, FileSystemLoader

from fabricgov.reporters.insights import InsightsEngine, ReportInsights

# Paleta de cores da identidade visual
COLORS_PRIMARY = ["#1e3a5f", "#2e6da4", "#4a9fd4", "#7ec8e3", "#b3dff5"]
COLORS_ACCENT = ["#e07b39", "#f0a500", "#4caf50", "#e53935", "#ab47bc"]
COLORS_STATUS = {
    "Completed": "#4caf50",
    "completed": "#4caf50",
    "Failed": "#e53935",
    "failed": "#e53935",
    "Unknown": "#9e9e9e",
    "Disabled": "#ff9800",
}

PLOTLY_LAYOUT = dict(
    paper_bgcolor="white",
    plot_bgcolor="white",
    font=dict(family="Segoe UI, Arial, sans-serif", size=12, color="#2c3e50"),
    margin=dict(l=20, r=20, t=30, b=20),
    legend=dict(orientation="h", yanchor="bottom", y=-0.3, xanchor="center", x=0.5),
)

# ---------------------------------------------------------------------------
# Traduções
# ---------------------------------------------------------------------------

TRANSLATIONS: dict[str, dict[str, str]] = {
    "pt": {
        "html_lang": "pt-BR",
        # Sidebar nav
        "nav_summary": "Resumo Executivo",
        "nav_inventory": "Inventário",
        "nav_workspaces": "Workspaces",
        "nav_access": "Acesso & Governança",
        "nav_refresh": "Saúde do Refresh",
        "nav_infra": "Infraestrutura",
        "nav_domains": "Domínios",
        "nav_findings": "Findings",
        "developed_by": "Desenvolvido por",
        # Header
        "generated_at": "Gerado em",
        # KPI labels
        "kpi_workspaces": "Workspaces",
        "kpi_total_artifacts": "Total de Artefatos",
        "kpi_unique_users": "Usuários Únicos",
        "kpi_external_users": "Usuários Externos",
        "kpi_datasets_without_owner": "Datasets sem Owner",
        "kpi_refresh_success_rate": "Taxa de Sucesso de Refresh",
        "kpi_workspaces_on_dedicated": "Workspaces em Dedicated Capacity",
        "kpi_total_workspaces": "Total de Workspaces",
        "kpi_on_dedicated": "Em Dedicated Capacity",
        "kpi_on_shared": "Em Shared Capacity",
        # Section titles
        "section_summary": "Resumo Executivo",
        "section_inventory": "Inventário",
        "section_workspaces": "Workspaces — Detalhe Completo",
        "section_access": "Acesso & Governança",
        "section_refresh": "Saúde do Refresh",
        "section_infra": "Infraestrutura",
        "section_domains": "Domínios do Tenant",
        "section_findings": "Findings de Governança",
        # Inventory
        "artifact_count_title": "Contagem por Tipo de Artefato",
        "col_type": "Tipo",
        "col_quantity": "Quantidade",
        # Workspaces
        "all_workspaces_table": "Todos os Workspaces (ordenado por artefatos)",
        "col_name": "Nome",
        "col_state": "Estado",
        "col_capacity": "Capacidade",
        "col_artifacts": "Artefatos",
        "artifacts_by_type": "Artefatos por Tipo",
        "top_artifact_owners_title": "Top Usuários por Artefatos Próprios",
        "col_owner": "Dono",
        "col_modified": "Últ. Modificação",
        # Access
        "external_users_title": "Usuários Externos com Acesso (#EXT#)",
        "no_external_users": "Nenhum usuário externo detectado.",
        "col_email": "Email",
        "col_roles": "Roles",
        "top_users_title": "Top 10 Usuários por Acessos",
        "single_user_title": "Workspaces com Apenas 1 Usuário (Ponto Único de Falha)",
        "col_user": "Usuário",
        "col_role": "Role",
        # Refresh
        "failed_refreshes_title": "Refreshes com Falha",
        "col_artifact": "Artefato",
        "col_start": "Início",
        "col_status": "Status",
        "stale_datasets_title": "Datasets sem Refresh nos Últimos 30 Dias",
        "col_last_refresh": "Último Refresh",
        "all_fresh": "Todos os datasets foram atualizados nos últimos 30 dias.",
        # Infra
        "capacities_title": "Capacidades",
        "col_region": "Região",
        "workloads_title": "Workloads por Estado",
        # Domains
        "col_description": "Descrição",
        "badge_subdomain": "Sub-domínio",
        "badge_root": "Raiz",
        # Findings
        "severity_label": "Severidade:",
        # Footer
        "footer_generated_by": "Gerado por",
        "footer_source": "Fonte:",
        "footer_developed_by": "Desenvolvido por",
        # Chart titles
        "chart_artifacts": "Artefatos por Tipo",
        "chart_workspace_type": "Tipos de Workspace",
        "chart_capacity_donut": "Dedicated vs Shared",
        "chart_top_workspaces": "Top 10 Workspaces (por artefatos)",
        "chart_roles": "Distribuição de Roles",
        "chart_principal_type": "Tipo de Principal",
        "chart_refresh_status": "Status de Refresh",
        "chart_refresh_timeline": "Refreshes por Dia (últimos 30 dias)",
        "chart_capacity_bar": "Workspaces por Capacidade",
        "chart_sku": "Capacidades por SKU",
        # Activity
        "nav_activity": "Log de Atividades",
        "section_activity": "Log de Atividades do Tenant",
        "kpi_total_events": "Total de Eventos",
        "kpi_active_users": "Usuários Ativos",
        "activity_top_activities_title": "Top 10 Tipos de Atividade",
        "activity_top_users_title": "Top 10 Usuários Mais Ativos",
        "activity_top_artifacts_title": "Top 10 Artefatos Mais Acessados",
        "col_activity": "Atividade",
        "col_events": "Eventos",
        "chart_activity_top": "Top Atividades",
        "chart_activity_timeline": "Eventos por Dia",
        # Diff / Trends
        "nav_trends": "Tendências",
        "section_trends": "Tendências — Comparativo de Snapshots",
        "diff_interval": "Intervalo entre snapshots",
        "diff_days": "dias",
        "diff_workspaces_added": "Workspaces Adicionados",
        "diff_workspaces_removed": "Workspaces Removidos",
        "diff_artifacts_added": "Artefatos Adicionados",
        "diff_artifacts_removed": "Artefatos Removidos",
        "diff_access_granted": "Permissões Concedidas",
        "diff_access_revoked": "Permissões Revogadas",
        "diff_degraded": "Datasets Degradados",
        "diff_improved": "Datasets Melhorados",
        "diff_findings_new": "Findings Novos",
        "diff_findings_resolved": "Findings Resolvidos",
        "diff_access_granted_title": "Permissões Concedidas",
        "diff_access_revoked_title": "Permissões Revogadas",
        "diff_degraded_title": "Datasets com Mais Falhas de Refresh",
        "diff_improved_title": "Datasets com Menos Falhas de Refresh",
        "diff_findings_new_title": "Novos Findings de Governança",
        "diff_findings_resolved_title": "Findings Resolvidos",
        "col_resource": "Recurso",
        "col_user": "Usuário",
        "col_failures_before": "Falhas Antes",
        "col_failures_after": "Falhas Depois",
        "chart_diff_overview": "Visão Geral do Comparativo",
        # Datasources
        "nav_datasources": "Datasources",
        "section_datasources": "Datasources & Conexões",
        "datasource_type_title": "Datasources por Tipo",
        "datasource_list_title": "Datasources por Dataset (Top 50)",
        "col_dataset": "Dataset",
        "col_datasource_type": "Tipo de Datasource",
        "col_connection": "Conexão",
        "kpi_datasource_types": "Tipos de Datasource",
        "kpi_misconfigured": "Datasources Mal-configurados",
        "chart_datasource_types": "Datasources por Tipo",
        # Artifact users
        "artifact_users_by_type_title": "Usuários Únicos por Tipo de Artefato",
        "top_artifact_users_title": "Top 10 Usuários por Artefatos com Acesso",
        "col_artifact_count": "Artefatos com Acesso",
        "chart_artifact_users_by_type": "Usuários por Tipo de Artefato",
    },
    "en": {
        "html_lang": "en",
        # Sidebar nav
        "nav_summary": "Executive Summary",
        "nav_inventory": "Inventory",
        "nav_workspaces": "Workspaces",
        "nav_access": "Access & Governance",
        "nav_refresh": "Refresh Health",
        "nav_infra": "Infrastructure",
        "nav_domains": "Domains",
        "nav_findings": "Findings",
        "developed_by": "Developed by",
        # Header
        "generated_at": "Generated at",
        # KPI labels
        "kpi_workspaces": "Workspaces",
        "kpi_total_artifacts": "Total Artifacts",
        "kpi_unique_users": "Unique Users",
        "kpi_external_users": "External Users",
        "kpi_datasets_without_owner": "Datasets without Owner",
        "kpi_refresh_success_rate": "Refresh Success Rate",
        "kpi_workspaces_on_dedicated": "Workspaces on Dedicated Capacity",
        "kpi_total_workspaces": "Total Workspaces",
        "kpi_on_dedicated": "On Dedicated Capacity",
        "kpi_on_shared": "On Shared Capacity",
        # Section titles
        "section_summary": "Executive Summary",
        "section_inventory": "Inventory",
        "section_workspaces": "Workspaces — Full Detail",
        "section_access": "Access & Governance",
        "section_refresh": "Refresh Health",
        "section_infra": "Infrastructure",
        "section_domains": "Tenant Domains",
        "section_findings": "Governance Findings",
        # Inventory
        "artifact_count_title": "Count by Artifact Type",
        "col_type": "Type",
        "col_quantity": "Quantity",
        # Workspaces
        "all_workspaces_table": "All Workspaces (sorted by artifacts)",
        "col_name": "Name",
        "col_state": "State",
        "col_capacity": "Capacity",
        "col_artifacts": "Artifacts",
        "artifacts_by_type": "Artifacts by Type",
        "top_artifact_owners_title": "Top Users by Owned Artifacts",
        "col_owner": "Owner",
        "col_modified": "Last Modified",
        # Access
        "external_users_title": "External Users with Access (#EXT#)",
        "no_external_users": "No external users detected.",
        "col_email": "Email",
        "col_roles": "Roles",
        "top_users_title": "Top 10 Users by Access",
        "single_user_title": "Workspaces with Only 1 User (Single Point of Failure)",
        "col_user": "User",
        "col_role": "Role",
        # Refresh
        "failed_refreshes_title": "Failed Refreshes",
        "col_artifact": "Artifact",
        "col_start": "Start",
        "col_status": "Status",
        "stale_datasets_title": "Datasets without Refresh in the Last 30 Days",
        "col_last_refresh": "Last Refresh",
        "all_fresh": "All datasets have been updated in the last 30 days.",
        # Infra
        "capacities_title": "Capacities",
        "col_region": "Region",
        "workloads_title": "Workloads by State",
        # Domains
        "col_description": "Description",
        "badge_subdomain": "Sub-domain",
        "badge_root": "Root",
        # Findings
        "severity_label": "Severity:",
        # Footer
        "footer_generated_by": "Generated by",
        "footer_source": "Source:",
        "footer_developed_by": "Developed by",
        # Chart titles
        "chart_artifacts": "Artifacts by Type",
        "chart_workspace_type": "Workspace Types",
        "chart_capacity_donut": "Dedicated vs Shared",
        "chart_top_workspaces": "Top 10 Workspaces (by artifacts)",
        "chart_roles": "Role Distribution",
        "chart_principal_type": "Principal Type",
        "chart_refresh_status": "Refresh Status",
        "chart_refresh_timeline": "Refreshes per Day (last 30 days)",
        "chart_capacity_bar": "Workspaces by Capacity",
        "chart_sku": "Capacities by SKU",
        # Activity
        "nav_activity": "Activity Log",
        "section_activity": "Tenant Activity Log",
        "kpi_total_events": "Total Events",
        "kpi_active_users": "Active Users",
        "activity_top_activities_title": "Top 10 Activity Types",
        "activity_top_users_title": "Top 10 Most Active Users",
        "activity_top_artifacts_title": "Top 10 Most Accessed Artifacts",
        "col_activity": "Activity",
        "col_events": "Events",
        "chart_activity_top": "Top Activities",
        "chart_activity_timeline": "Events per Day",
        # Diff / Trends
        "nav_trends": "Trends",
        "section_trends": "Trends — Snapshot Comparison",
        "diff_interval": "Interval between snapshots",
        "diff_days": "days",
        "diff_workspaces_added": "Workspaces Added",
        "diff_workspaces_removed": "Workspaces Removed",
        "diff_artifacts_added": "Artifacts Added",
        "diff_artifacts_removed": "Artifacts Removed",
        "diff_access_granted": "Permissions Granted",
        "diff_access_revoked": "Permissions Revoked",
        "diff_degraded": "Degraded Datasets",
        "diff_improved": "Improved Datasets",
        "diff_findings_new": "New Findings",
        "diff_findings_resolved": "Resolved Findings",
        "diff_access_granted_title": "Granted Permissions",
        "diff_access_revoked_title": "Revoked Permissions",
        "diff_degraded_title": "Datasets with More Refresh Failures",
        "diff_improved_title": "Datasets with Fewer Refresh Failures",
        "diff_findings_new_title": "New Governance Findings",
        "diff_findings_resolved_title": "Resolved Findings",
        "col_resource": "Resource",
        "col_user": "User",
        "col_failures_before": "Failures Before",
        "col_failures_after": "Failures After",
        "chart_diff_overview": "Comparison Overview",
        # Datasources
        "nav_datasources": "Datasources",
        "section_datasources": "Datasources & Connections",
        "datasource_type_title": "Datasources by Type",
        "datasource_list_title": "Datasources by Dataset (Top 50)",
        "col_dataset": "Dataset",
        "col_datasource_type": "Datasource Type",
        "col_connection": "Connection",
        "kpi_datasource_types": "Datasource Types",
        "kpi_misconfigured": "Misconfigured Datasources",
        "chart_datasource_types": "Datasources by Type",
        # Artifact users
        "artifact_users_by_type_title": "Unique Users by Artifact Type",
        "top_artifact_users_title": "Top 10 Users by Artifacts with Access",
        "col_artifact_count": "Artifacts with Access",
        "chart_artifact_users_by_type": "Users by Artifact Type",
    },
}


class HtmlReporter:
    def __init__(self, source_dir: str | Path):
        self.source_dir = Path(source_dir)
        self._templates_dir = Path(__file__).parent / "templates"

    def generate(self, output_path: str | Path, lang: str = "pt") -> str:
        """Gera uma versão do relatório no idioma indicado."""
        output_path = Path(output_path)
        t = TRANSLATIONS.get(lang, TRANSLATIONS["pt"])
        insights = InsightsEngine(self.source_dir).compute()
        charts = self._build_charts(insights, t)
        html = self._render_template(insights, charts, t, lang)
        output_path.write_text(html, encoding="utf-8")
        return str(output_path)

    def generate_all(self, output_dir: str | Path | None = None) -> dict[str, str]:
        """Gera PT (report.html) e EN (report.en.html). Retorna {lang: caminho}."""
        base = Path(output_dir) if output_dir else self.source_dir
        insights = InsightsEngine(self.source_dir).compute()
        results: dict[str, str] = {}
        for lang, filename in [("pt", "report.html"), ("en", "report.en.html")]:
            t = TRANSLATIONS[lang]
            charts = self._build_charts(insights, t)
            html = self._render_template(insights, charts, t, lang)
            out = base / filename
            out.write_text(html, encoding="utf-8")
            results[lang] = str(out)
        return results

    # ------------------------------------------------------------------
    # Charts
    # ------------------------------------------------------------------

    def _fig_to_div(self, fig: go.Figure) -> str:
        return fig.to_html(full_html=False, include_plotlyjs=False, config={"responsive": True})

    def _build_charts(self, ins: ReportInsights, t: dict) -> dict[str, str]:
        charts: dict[str, str] = {}

        if ins.artifacts_by_type:
            charts["artifacts_bar"] = self._chart_artifacts_bar(ins, t)

        if ins.workspace_type_counts:
            charts["workspace_type_donut"] = self._chart_workspace_type(ins, t)

        if ins.workspaces_on_dedicated + ins.workspaces_on_shared > 0:
            charts["capacity_donut"] = self._chart_capacity_donut(ins, t)

        if ins.top_workspaces:
            charts["top_workspaces_bar"] = self._chart_top_workspaces(ins, t)

        if ins.role_distribution:
            charts["role_donut"] = self._chart_role_donut(ins, t)

        if ins.principal_type_dist:
            charts["principal_type_donut"] = self._chart_principal_type(ins, t)

        if ins.refresh_status_counts:
            charts["refresh_status_donut"] = self._chart_refresh_status(ins, t)

        if ins.refresh_timeline:
            charts["refresh_timeline"] = self._chart_refresh_timeline(ins, t)

        if ins.capacity_workspace_counts:
            charts["capacity_bar"] = self._chart_capacity_bar(ins, t)

        if ins.sku_counts:
            charts["sku_bar"] = self._chart_sku_bar(ins, t)

        if ins.activity_top_activities:
            charts["activity_top"] = self._chart_activity_top(ins, t)

        if ins.activity_timeline:
            charts["activity_timeline"] = self._chart_activity_timeline(ins, t)

        if ins.datasource_type_counts:
            charts["datasource_types"] = self._chart_datasource_types(ins, t)

        if ins.artifact_users_by_type:
            charts["artifact_users_by_type"] = self._chart_artifact_users_by_type(ins, t)

        if ins.has_diff_data and ins.diff_summary:
            charts["diff_overview"] = self._chart_diff_overview(ins, t)

        return charts

    def _chart_artifacts_bar(self, ins: ReportInsights, t: dict) -> str:
        items = sorted(ins.artifacts_by_type.items(), key=lambda x: x[1], reverse=True)[:12]
        labels, values = zip(*items) if items else ([], [])
        fig = go.Figure(go.Bar(
            x=list(values), y=list(labels), orientation="h",
            marker_color=COLORS_PRIMARY[1],
            text=list(values), textposition="outside",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_artifacts"],
                          yaxis=dict(autorange="reversed"), showlegend=False)
        return self._fig_to_div(fig)

    def _chart_workspace_type(self, ins: ReportInsights, t: dict) -> str:
        labels = list(ins.workspace_type_counts.keys())
        values = list(ins.workspace_type_counts.values())
        fig = go.Figure(go.Pie(
            labels=labels, values=values, hole=0.45,
            marker_colors=COLORS_PRIMARY,
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_workspace_type"])
        return self._fig_to_div(fig)

    def _chart_capacity_donut(self, ins: ReportInsights, t: dict) -> str:
        fig = go.Figure(go.Pie(
            labels=["Dedicated Capacity", "Shared Capacity"],
            values=[ins.workspaces_on_dedicated, ins.workspaces_on_shared],
            hole=0.45,
            marker_colors=["#1e3a5f", "#b3dff5"],
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_capacity_donut"])
        return self._fig_to_div(fig)

    def _chart_top_workspaces(self, ins: ReportInsights, t: dict) -> str:
        names = [w["name"][:35] + "…" if len(w["name"]) > 35 else w["name"]
                 for w in ins.top_workspaces]
        values = [w["count"] for w in ins.top_workspaces]
        fig = go.Figure(go.Bar(
            x=values, y=names, orientation="h",
            marker_color=COLORS_ACCENT[0],
            text=values, textposition="outside",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_top_workspaces"],
                          yaxis=dict(autorange="reversed"), showlegend=False)
        return self._fig_to_div(fig)

    def _chart_role_donut(self, ins: ReportInsights, t: dict) -> str:
        labels = list(ins.role_distribution.keys())
        values = list(ins.role_distribution.values())
        fig = go.Figure(go.Pie(
            labels=labels, values=values, hole=0.45,
            marker_colors=COLORS_PRIMARY + COLORS_ACCENT,
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_roles"])
        return self._fig_to_div(fig)

    def _chart_principal_type(self, ins: ReportInsights, t: dict) -> str:
        labels = list(ins.principal_type_dist.keys())
        values = list(ins.principal_type_dist.values())
        fig = go.Figure(go.Pie(
            labels=labels, values=values, hole=0.45,
            marker_colors=COLORS_ACCENT,
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_principal_type"])
        return self._fig_to_div(fig)

    def _chart_refresh_status(self, ins: ReportInsights, t: dict) -> str:
        labels = list(ins.refresh_status_counts.keys())
        values = list(ins.refresh_status_counts.values())
        colors = [COLORS_STATUS.get(lbl, "#9e9e9e") for lbl in labels]
        fig = go.Figure(go.Pie(
            labels=labels, values=values, hole=0.45,
            marker_colors=colors,
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_refresh_status"])
        return self._fig_to_div(fig)

    def _chart_refresh_timeline(self, ins: ReportInsights, t: dict) -> str:
        dates = [r["date"] for r in ins.refresh_timeline]
        counts = [r["count"] for r in ins.refresh_timeline]
        fig = go.Figure(go.Scatter(
            x=dates, y=counts, mode="lines+markers",
            line=dict(color=COLORS_PRIMARY[1], width=2),
            marker=dict(size=6),
            fill="tozeroy", fillcolor="rgba(46,109,164,0.1)",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_refresh_timeline"],
                          showlegend=False)
        return self._fig_to_div(fig)

    def _chart_capacity_bar(self, ins: ReportInsights, t: dict) -> str:
        items = sorted(ins.capacity_workspace_counts.items(), key=lambda x: x[1], reverse=True)
        labels = [k[:30] for k, _ in items]
        values = [v for _, v in items]
        fig = go.Figure(go.Bar(
            x=labels, y=values,
            marker_color=COLORS_PRIMARY[0],
            text=values, textposition="outside",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_capacity_bar"],
                          showlegend=False)
        return self._fig_to_div(fig)

    def _chart_sku_bar(self, ins: ReportInsights, t: dict) -> str:
        labels = list(ins.sku_counts.keys())
        values = list(ins.sku_counts.values())
        fig = go.Figure(go.Bar(
            x=labels, y=values,
            marker_color=COLORS_ACCENT[2],
            text=values, textposition="outside",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_sku"],
                          showlegend=False)
        return self._fig_to_div(fig)

    def _chart_activity_top(self, ins: ReportInsights, t: dict) -> str:
        items = ins.activity_top_activities[:10]
        labels = [i["activity"] for i in reversed(items)]
        values = [i["count"] for i in reversed(items)]
        fig = go.Figure(go.Bar(
            x=values, y=labels, orientation="h",
            marker_color=COLORS_PRIMARY[2],
            text=values, textposition="outside",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_activity_top"],
                          showlegend=False)
        return self._fig_to_div(fig)

    def _chart_activity_timeline(self, ins: ReportInsights, t: dict) -> str:
        dates = [r["date"] for r in ins.activity_timeline]
        counts = [r["count"] for r in ins.activity_timeline]
        fig = go.Figure(go.Scatter(
            x=dates, y=counts, mode="lines+markers",
            line=dict(color=COLORS_ACCENT[0], width=2),
            marker=dict(size=5),
            fill="tozeroy", fillcolor="rgba(224,123,57,0.1)",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_activity_timeline"],
                          showlegend=False)
        return self._fig_to_div(fig)

    def _chart_datasource_types(self, ins: ReportInsights, t: dict) -> str:
        items = sorted(ins.datasource_type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        labels, values = zip(*items) if items else ([], [])
        fig = go.Figure(go.Bar(
            x=list(values), y=list(labels), orientation="h",
            marker_color=COLORS_PRIMARY[2],
            text=list(values), textposition="outside",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_datasource_types"],
                          showlegend=False)
        return self._fig_to_div(fig)

    def _chart_artifact_users_by_type(self, ins: ReportInsights, t: dict) -> str:
        items = sorted(ins.artifact_users_by_type.items(), key=lambda x: x[1], reverse=True)[:12]
        labels, values = zip(*items) if items else ([], [])
        fig = go.Figure(go.Bar(
            x=list(values), y=list(labels), orientation="h",
            marker_color=COLORS_ACCENT[0],
            text=list(values), textposition="outside",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_artifact_users_by_type"],
                          showlegend=False)
        return self._fig_to_div(fig)

    def _chart_diff_overview(self, ins: ReportInsights, t: dict) -> str:
        s = ins.diff_summary
        categories = [
            t["diff_workspaces_added"], t["diff_workspaces_removed"],
            t["diff_artifacts_added"], t["diff_artifacts_removed"],
            t["diff_access_granted"], t["diff_access_revoked"],
            t["diff_findings_new"], t["diff_findings_resolved"],
        ]
        values = [
            s.get("workspaces_added", 0), s.get("workspaces_removed", 0),
            s.get("artifacts_added", 0), s.get("artifacts_removed", 0),
            s.get("access_granted", 0), s.get("access_revoked", 0),
            s.get("findings_new", 0), s.get("findings_resolved", 0),
        ]
        colors = [
            COLORS_ACCENT[2], COLORS_ACCENT[3],
            COLORS_ACCENT[2], COLORS_ACCENT[3],
            COLORS_ACCENT[2], COLORS_ACCENT[3],
            COLORS_ACCENT[3], COLORS_ACCENT[2],
        ]
        fig = go.Figure(go.Bar(
            x=values, y=categories, orientation="h",
            marker_color=colors,
            text=values, textposition="outside",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title=t["chart_diff_overview"],
                          showlegend=False, yaxis=dict(autorange="reversed"))
        return self._fig_to_div(fig)

    # ------------------------------------------------------------------
    # Template
    # ------------------------------------------------------------------

    def _render_template(
        self,
        ins: ReportInsights,
        charts: dict[str, str],
        t: dict,
        lang: str,
    ) -> str:
        env = Environment(
            loader=FileSystemLoader(str(self._templates_dir)),
            autoescape=True,
        )
        template = env.get_template("report.html.j2")
        return template.render(ins=ins, charts=charts, t=t, lang=lang)
