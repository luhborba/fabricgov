"""
CLI: fabricgov analyze
Analisa os dados coletados e exibe findings de governança no terminal.
Salva findings.json com detalhe completo na pasta de origem.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box


# Mapeamento de severidade → estilo rich
_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold cyan",
    "OK":       "bold green",
}

_DETAIL_LABELS = {
    "pt": {
        "title":        "Análise de Governança",
        "generated_at": "Gerado em",
        "col_severity": "Severidade",
        "col_count":    "Count",
        "col_finding":  "Finding",
        "saved":        "findings.json salvo em",
        "no_data":      "Nenhum arquivo de dados encontrado em",
        "run_hint":     "Execute os collectors antes de analisar.",
        "not_found":    "Pasta não encontrada",
    },
    "en": {
        "title":        "Governance Analysis",
        "generated_at": "Generated at",
        "col_severity": "Severity",
        "col_count":    "Count",
        "col_finding":  "Finding",
        "saved":        "findings.json saved to",
        "no_data":      "No data files found in",
        "run_hint":     "Run the collectors before analyzing.",
        "not_found":    "Folder not found",
    },
}

# Máximo de linhas de detalhe a exibir por finding no terminal
_DETAIL_LIMIT = 10


def _find_latest_run(output_dir: str) -> Path | None:
    base = Path(output_dir)
    if not base.exists():
        return None
    pattern = re.compile(r"^\d{8}_\d{6}$")
    candidates = [d for d in base.iterdir() if d.is_dir() and pattern.match(d.name)]
    if not candidates:
        return None
    return max(candidates, key=lambda d: d.name)


def _detail_rows(finding: dict) -> list[str]:
    """Formata as primeiras _DETAIL_LIMIT linhas de detalhe como strings."""
    details = finding.get("details", [])
    if not details:
        return []
    lines = []
    for row in details[:_DETAIL_LIMIT]:
        # Monta uma linha legível independente dos campos disponíveis
        if "name" in row and "workspace_name" in row:
            lines.append(f"  • {row['name']:<40} — {row['workspace_name']}")
        elif "email" in row:
            roles = row.get("roles", "—")
            ws = row.get("workspace_count", "?")
            lines.append(f"  • {row['email']:<45} {roles} ({ws} ws)")
        elif "workspace" in row and "user_email" in row:
            lines.append(f"  • {row['workspace']:<40} — {row['user_email']}")
        elif "artifact_name" in row:
            status = row.get("status", "—")
            ws = row.get("workspace_name", "—")
            lines.append(f"  • {row['artifact_name']:<40} [{status}] {ws}")
        else:
            lines.append(f"  • {str(row)}")
    remaining = len(details) - _DETAIL_LIMIT
    if remaining > 0:
        lines.append(f"  ... e mais {remaining} (ver findings.json)")
    return lines


@click.command("analyze")
@click.option(
    "--from", "source", default=None,
    help="Pasta de output com os dados (padrão: pasta mais recente em output/).",
)
@click.option(
    "--output-dir", default=None,
    help="Onde salvar findings.json (padrão: mesma pasta dos dados).",
)
@click.option(
    "--lang", default="pt", type=click.Choice(["pt", "en"]), show_default=True,
    help="Idioma das mensagens no terminal.",
)
@click.option(
    "--output-root", default="output", show_default=True,
    help="Diretório raiz onde procurar o run mais recente (usado quando --from não é informado).",
)
def analyze_cmd(source: str | None, output_dir: str | None, lang: str, output_root: str) -> None:
    """Analisa os dados coletados e exibe findings de governança no terminal.

    \\b
    Exemplos:
      fabricgov analyze                                        # pasta mais recente em output/
      fabricgov analyze --from output/20260227_143000/         # pasta específica
      fabricgov analyze --from output/20260227_143000/ --lang en
    """
    from fabricgov.reporters.insights import InsightsEngine

    console = Console()
    lbl = _DETAIL_LABELS.get(lang, _DETAIL_LABELS["pt"])

    # ── Resolve pasta de dados ──
    if source:
        source_path = Path(source)
        if not source_path.exists():
            console.print(f"[red]❌ {lbl['not_found']}: {source}[/red]")
            raise SystemExit(1)
    else:
        source_path = _find_latest_run(output_root)
        if source_path is None:
            console.print(
                f"[red]❌ {lbl['no_data']} '{output_root}/'. {lbl['run_hint']}[/red]"
            )
            raise SystemExit(1)

    data_files = list(source_path.glob("*.csv")) + list(source_path.glob("*.json"))
    if not data_files:
        console.print(f"[red]❌ {lbl['no_data']} '{source_path}'. {lbl['run_hint']}[/red]")
        raise SystemExit(1)

    # ── Computa insights ──
    insights = InsightsEngine(source_path).compute()

    # ── Cabeçalho ──
    console.print(Panel(
        f"[bold]{lbl['title']}[/bold] — [dim]{source_path}[/dim]\n"
        f"{lbl['generated_at']}: {insights.generated_at}",
        box=box.DOUBLE,
        expand=False,
    ))

    # ── Tabela de findings ──
    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold")
    table.add_column(lbl["col_severity"], width=12)
    table.add_column(lbl["col_count"], justify="right", width=7)
    table.add_column(lbl["col_finding"])

    for f in insights.findings:
        sev = f["severity"]
        style = _SEVERITY_STYLE.get(sev, "")
        msg = f["message_en"] if lang == "en" else f["message"]
        icon = f.get("icon", "")
        table.add_row(
            f"[{style}]{icon} {sev}[/{style}]",
            str(f["count"]),
            msg,
        )

    console.print(table)

    # ── Detalhe por finding ──
    for f in insights.findings:
        if f["severity"] == "OK" or not f.get("details"):
            continue
        msg = f["message_en"] if lang == "en" else f["message"]
        sev = f["severity"]
        style = _SEVERITY_STYLE.get(sev, "")
        console.print(f"\n[{style}]{f.get('icon','')} {msg}[/{style}]")
        for line in _detail_rows(f):
            console.print(line)

    # ── Salva findings.json ──
    out_dir = Path(output_dir) if output_dir else source_path
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "findings.json"

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "ok": 0}
    for f in insights.findings:
        key = f["severity"].lower()
        if key in severity_counts:
            severity_counts[key] += 1

    payload = {
        "generated_at": insights.generated_at,
        "source_folder": str(source_path),
        "summary": {
            "total_findings": len([f for f in insights.findings if f["severity"] != "OK"]),
            **severity_counts,
        },
        "findings": [
            {
                "severity": f["severity"],
                "count": f["count"],
                "message": f["message"],
                "message_en": f["message_en"],
                "details": f.get("details", []),
            }
            for f in insights.findings
        ],
    }

    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    console.print(f"\n[green]✅ {lbl['saved']} {json_path}[/green]")
