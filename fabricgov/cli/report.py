"""
CLI: fabricgov report
Gera relatório HTML a partir de uma pasta de output do fabricgov.
"""
from __future__ import annotations

import re
import webbrowser
from pathlib import Path

import click


def _find_latest_run(output_dir: str) -> Path | None:
    """Encontra a pasta YYYYMMDD_HHMMSS mais recente em output_dir."""
    base = Path(output_dir)
    if not base.exists():
        return None
    pattern = re.compile(r"^\d{8}_\d{6}$")
    candidates = [
        d for d in base.iterdir()
        if d.is_dir() and pattern.match(d.name)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda d: d.name)


@click.command("report")
@click.option(
    "--from", "source", default=None,
    help="Pasta de output com os dados (padrão: pasta mais recente em output/).",
)
@click.option(
    "--output", default=None,
    help="Caminho do arquivo HTML gerado (padrão: <source>/report.html).",
)
@click.option(
    "--output-dir", default="output", show_default=True,
    help="Diretório raiz onde procurar o run mais recente (usado quando --from não é informado).",
)
@click.option(
    "--open/--no-open", "open_browser", default=False,
    help="Abrir o relatório no browser após geração.",
)
def report_cmd(source: str | None, output: str | None, output_dir: str, open_browser: bool) -> None:
    """Gera um relatório HTML de governança a partir dos dados coletados.

    \b
    Exemplos:
      fabricgov report                                       # pasta mais recente em output/
      fabricgov report --from output/20260226_143000/        # pasta específica
      fabricgov report --from output/20260226_143000/ --open # abre no browser
      fabricgov report --output ~/reports/governance.html
    """
    from fabricgov.reporters import HtmlReporter

    # ── Resolve pasta de dados ──
    if source:
        source_path = Path(source)
        if not source_path.exists():
            click.echo(f"❌ Pasta não encontrada: {source}", err=True)
            raise SystemExit(1)
    else:
        source_path = _find_latest_run(output_dir)
        if source_path is None:
            click.echo(
                f"❌ Nenhuma pasta de output encontrada em '{output_dir}/'. "
                "Execute 'fabricgov collect inventory' primeiro ou use --from.",
                err=True,
            )
            raise SystemExit(1)
        click.echo(f"📂 Usando pasta mais recente: {source_path}")

    # Verifica se tem algum arquivo de dados
    data_files = list(source_path.glob("*.csv")) + list(source_path.glob("*.json"))
    if not data_files:
        click.echo(
            f"❌ Nenhum arquivo de dados encontrado em '{source_path}'. "
            "Execute os collectors antes de gerar o relatório.",
            err=True,
        )
        raise SystemExit(1)

    # ── Gera relatório ──
    click.echo("⚙️  Computando métricas e gerando gráficos...")
    try:
        reporter = HtmlReporter(source_path)
        if output:
            # Saída explícita: gera apenas PT no caminho informado
            result = reporter.generate(Path(output), lang="pt")
            click.echo(f"✅ Relatório gerado: {result}")
            open_path = result
        else:
            # Gera PT + EN automaticamente na mesma pasta
            results = reporter.generate_all(source_path)
            click.echo(f"✅ Relatório PT: {results['pt']}")
            click.echo(f"✅ Relatório EN: {results['en']}")
            open_path = results["pt"]
    except Exception as e:
        click.echo(f"❌ Erro ao gerar relatório: {e}", err=True)
        raise SystemExit(1)

    if open_browser:
        click.echo("🌐 Abrindo no browser...")
        webbrowser.open(Path(open_path).resolve().as_uri())
