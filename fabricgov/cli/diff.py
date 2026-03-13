"""
CLI: fabricgov diff
Compara dois snapshots de output do fabricgov e gera diff.json.
"""
from __future__ import annotations

import sys
from pathlib import Path

import click


@click.command("diff")
@click.option(
    "--from", "snap_from", default=None,
    help="Snapshot base/antigo (pasta YYYYMMDD_HHMMSS). Padrão: penúltimo run.",
)
@click.option(
    "--to", "snap_to", default=None,
    help="Snapshot atual/novo (pasta YYYYMMDD_HHMMSS). Padrão: último run.",
)
@click.option(
    "--output-dir", default="output", show_default=True,
    help="Diretório raiz onde procurar os snapshots (quando --from/--to não informados).",
)
@click.option(
    "--output", default=None,
    help="Caminho do diff.json gerado (padrão: <to>/diff.json).",
)
def diff_cmd(snap_from: str | None, snap_to: str | None, output_dir: str, output: str | None) -> None:
    """Compara dois snapshots de governança e gera diff.json.

    \b
    Exemplos:
      fabricgov diff                                                  # 2 runs mais recentes
      fabricgov diff --from output/20260301_120000 --to output/20260309_143000
      fabricgov diff --output ~/reports/diff.json
    """
    from fabricgov.diff.snapshot import Snapshot, find_run_dirs
    from fabricgov.diff.engine import DiffEngine

    # ── Resolve os dois snapshots ──
    if snap_from and snap_to:
        path_from = Path(snap_from)
        path_to = Path(snap_to)
        for p in [path_from, path_to]:
            if not p.exists():
                click.echo(f"❌ Pasta não encontrada: {p}", err=True)
                sys.exit(1)
    else:
        runs = find_run_dirs(output_dir)
        if len(runs) < 2:
            click.echo(
                f"❌ São necessárias ao menos 2 pastas de output em '{output_dir}/'. "
                "Use --from e --to para especificar explicitamente.",
                err=True,
            )
            sys.exit(1)
        path_from = runs[-2]
        path_to = runs[-1]
        click.echo("📂 Snapshots detectados automaticamente:")
        click.echo(f"   De:   {path_from.name}  ({path_from.name[:4]}-{path_from.name[4:6]}-{path_from.name[6:8]} {path_from.name[9:11]}:{path_from.name[11:13]})")
        click.echo(f"   Para: {path_to.name}  ({path_to.name[:4]}-{path_to.name[4:6]}-{path_to.name[6:8]} {path_to.name[9:11]}:{path_to.name[11:13]})")

    snap_a = Snapshot(path_from)
    snap_b = Snapshot(path_to)

    click.echo("⚙️  Computando diff...")
    engine = DiffEngine(snap_a, snap_b)
    result = engine.run()

    # ── Salva diff.json ──
    out_path = Path(output) if output else path_to / "diff.json"
    result.save(out_path)

    # ── Resumo executivo no terminal ──
    _print_summary(result)
    click.echo(f"\n✅ diff.json salvo em: {out_path}")


def _print_summary(result) -> None:
    """Exibe resumo executivo no terminal."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box

        console = Console()
        s = result.summary
        m = result.meta

        console.print()
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
        console.print("[bold cyan]  fabricgov diff — Resumo Executivo[/]")
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
        console.print(f"  [dim]Intervalo:[/] {m.get('days_between', '?')} dias entre snapshots")
        console.print()

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column("Seção", style="bold", min_width=14)
        table.add_column("Alterações")

        def _row(label: str, parts: list[str]) -> None:
            table.add_row(label, "  ".join(parts) if parts else "[dim]sem alterações[/]")

        # Workspaces
        ws_parts = []
        if s["workspaces_added"]:   ws_parts.append(f"[green]+{s['workspaces_added']} adicionados[/]")
        if s["workspaces_removed"]: ws_parts.append(f"[red]-{s['workspaces_removed']} removidos[/]")
        if s["workspaces_changed"]: ws_parts.append(f"[yellow]~{s['workspaces_changed']} alterados[/]")
        _row("Workspaces", ws_parts)

        # Artefatos
        art_parts = []
        if s["artifacts_added"]:   art_parts.append(f"[green]+{s['artifacts_added']} adicionados[/]")
        if s["artifacts_removed"]: art_parts.append(f"[red]-{s['artifacts_removed']} removidos[/]")
        _row("Artefatos", art_parts)

        # Acesso
        acc_parts = []
        if s["access_granted"]:      acc_parts.append(f"[green]+{s['access_granted']} concedidas[/]")
        if s["access_revoked"]:      acc_parts.append(f"[red]-{s['access_revoked']} revogadas[/]")
        if s["access_role_changed"]: acc_parts.append(f"[yellow]~{s['access_role_changed']} papel alterado[/]")
        _row("Acesso", acc_parts)

        # Refresh
        ref_parts = []
        if s["datasets_degraded"]:  ref_parts.append(f"[red]↓ {s['datasets_degraded']} degradados[/]")
        if s["datasets_improved"]:  ref_parts.append(f"[green]↑ {s['datasets_improved']} melhorados[/]")
        if s["schedules_added"]:    ref_parts.append(f"[green]+{s['schedules_added']} schedules[/]")
        if s["schedules_removed"]:  ref_parts.append(f"[red]-{s['schedules_removed']} schedules[/]")
        _row("Refresh", ref_parts)

        # Findings
        find_parts = []
        if s["findings_new"]:           find_parts.append(f"[red]⚠ {s['findings_new']} novos[/]")
        if s["findings_resolved"]:      find_parts.append(f"[green]✓ {s['findings_resolved']} resolvidos[/]")
        if s["findings_count_changed"]: find_parts.append(f"[yellow]~ {s['findings_count_changed']} contagem alterada[/]")
        _row("Findings", find_parts)

        console.print(table)

    except ImportError:
        # Fallback sem rich
        s = result.summary
        print("\nfabricgov diff — Resumo Executivo")
        print(f"  Workspaces : +{s['workspaces_added']} -{s['workspaces_removed']} ~{s['workspaces_changed']}")
        print(f"  Artefatos  : +{s['artifacts_added']} -{s['artifacts_removed']}")
        print(f"  Acesso     : +{s['access_granted']} -{s['access_revoked']} ~{s['access_role_changed']}")
        print(f"  Refresh    : ↓{s['datasets_degraded']} ↑{s['datasets_improved']}")
        print(f"  Findings   : ⚠{s['findings_new']} ✓{s['findings_resolved']}")
