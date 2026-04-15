import click
import json
from pathlib import Path
from datetime import datetime
from fabricgov.auth import ServicePrincipalAuth, DeviceFlowAuth, KeyVaultAuth
from fabricgov.collectors import (
    WorkspaceInventoryCollector,
    WorkspaceAccessCollector,
    RefreshHistoryCollector,
    RefreshScheduleCollector,
    DomainCollector,
    TagCollector,
    CapacityCollector,
    WorkloadCollector,
    ActivityCollector,
)
from fabricgov.exporters import FileExporter
from fabricgov.exceptions import CheckpointSavedException
from fabricgov.config import get_auth_preference, get_keyvault_config, require_auth
from fabricgov.progress import ProgressManager, create_progress_callback
from fabricgov.cli.session import (
    load_session,
    save_session,
    clear_session,
    create_new_session,
    mark_step_completed,
    mark_step_checkpointed,
    mark_step_failed,
    get_step_status,
    find_pending_checkpoints,
    is_session_complete,
)

# Sinal para o orquestrador 'all' distinguir checkpoint de erro real.
# Setado para True antes de raise click.Abort() quando é CheckpointSavedException.
_checkpoint_abort: bool = False


@click.group()
def collect():
    """Comandos de coleta de dados"""
    pass


def progress_callback(msg: str):
    """Callback para exibir progresso"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    click.echo(f"[{timestamp}] {msg}")


# ── inventory ────────────────────────────────────────────────────────────────

@collect.command()
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--progress/--no-progress', default=True, help='Mostrar progress bars')
@click.option('--run-dir', default=None, hidden=True, help='Diretório de sessão fixo (usado pelo all)')
def inventory(format, output, progress, run_dir):
    """
    Coleta inventário completo de workspaces e artefatos

    Exemplo:
        fabricgov collect inventory
        fabricgov collect inventory --no-progress
    """
    global _checkpoint_abort
    click.echo("="*70)
    click.echo("COLETA DE INVENTÁRIO")
    click.echo("="*70)

    try:
        auth = get_auth_provider()

        with ProgressManager(enabled=progress) as pm:
            cb = create_progress_callback(pm)

            collector = WorkspaceInventoryCollector(
                auth=auth,
                progress_callback=cb,
                progress_manager=pm if progress else None
            )
            result = collector.collect()

        # Salva inventory_result.json
        inventory_path = Path(output) / "inventory_result.json"
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        with open(inventory_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        click.echo(f"\n✓ Inventário salvo em: {inventory_path}")

        exporter = FileExporter(format=format, output_dir=output, run_dir=run_dir)
        output_path = exporter.export(result, [])

        click.echo(f"✓ Arquivos exportados em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("INVENTÁRIO CONCLUÍDO")
        click.echo("="*70)
        click.echo(f"Total de workspaces: {result['summary']['total_workspaces']}")
        click.echo(f"Total de itens: {result['summary']['total_items']}")
        click.echo("="*70)

    except Exception as e:
        _checkpoint_abort = False
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


# ── workspace-access ─────────────────────────────────────────────────────────

@collect.command('workspace-access')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--resume/--no-resume', default=True, help='Retomar de checkpoint')
@click.option('--progress/--no-progress', default=True, help='Mostrar progress bars')
@click.option('--run-dir', default=None, hidden=True, help='Diretório de sessão fixo (usado pelo all)')
def workspace_access(format, output, resume, progress, run_dir):
    """
    Coleta roles de acesso em workspaces

    Exemplo:
        fabricgov collect workspace-access
        fabricgov collect workspace-access --no-resume
    """
    global _checkpoint_abort
    click.echo("="*70)
    click.echo("COLETA DE ACESSOS EM WORKSPACES")
    click.echo("="*70)

    inventory_path = Path(output) / "inventory_result.json"
    if not inventory_path.exists():
        click.echo("❌ Erro: Execute 'fabricgov collect inventory' primeiro!", err=True)
        _checkpoint_abort = False
        raise click.Abort()

    with open(inventory_path, "r", encoding="utf-8") as f:
        inventory_result = json.load(f)

    try:
        auth = get_auth_provider()

        checkpoint_file = Path(output) / "checkpoint_workspace_access.json" if resume else None

        with ProgressManager(enabled=progress) as pm:
            cb = create_progress_callback(pm)

            collector = WorkspaceAccessCollector(
                auth=auth,
                inventory_result=inventory_result,
                progress_callback=cb,
                checkpoint_file=str(checkpoint_file) if checkpoint_file else None,
                progress_manager=pm if progress else None
            )

            result = collector.collect()

        exporter = FileExporter(format=format, output_dir=output, run_dir=run_dir)
        output_path = exporter.export(result, [])

        click.echo(f"\n✓ Workspace access exportado em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("COLETA CONCLUÍDA")
        click.echo("="*70)
        click.echo(f"Total de acessos: {len(result['workspace_access'])}")
        click.echo(f"Erros: {len(result['workspace_access_errors'])}")
        click.echo("="*70)

    except CheckpointSavedException as e:
        click.echo("\n" + "="*70)
        click.echo("COLETA INTERROMPIDA")
        click.echo("="*70)
        click.echo(f"⏹️  {e.progress} workspaces processados")
        click.echo(f"💾 Checkpoint: {e.checkpoint_file}")
        click.echo(f"⏰ Aguarde ~1 hora e execute novamente para retomar")
        click.echo("="*70)
        _checkpoint_abort = True
        raise click.Abort()

    except Exception as e:
        _checkpoint_abort = False
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


# ── refresh-history ───────────────────────────────────────────────────────────

@collect.command('refresh-history')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--resume/--no-resume', default=True, help='Retomar de checkpoint')
@click.option('--limit', default=100, help='Número máximo de refreshes por artefato')
@click.option('--progress/--no-progress', default=True, help='Mostrar progress bars')
@click.option('--run-dir', default=None, hidden=True, help='Diretório de sessão fixo (usado pelo all)')
def refresh_history(format, output, resume, limit, progress, run_dir):
    """
    Coleta histórico de execuções (refreshes) de datasets e dataflows

    Exemplo:
        fabricgov collect refresh-history
        fabricgov collect refresh-history --limit 50
    """
    global _checkpoint_abort
    click.echo("="*70)
    click.echo("COLETA DE HISTÓRICO DE REFRESHES")
    click.echo("="*70)

    inventory_path = Path(output) / "inventory_result.json"
    if not inventory_path.exists():
        click.echo("❌ Erro: Execute 'fabricgov collect inventory' primeiro!", err=True)
        _checkpoint_abort = False
        raise click.Abort()

    with open(inventory_path, "r", encoding="utf-8") as f:
        inventory_result = json.load(f)

    try:
        auth = get_auth_provider()

        checkpoint_file = Path(output) / "checkpoint_refresh_history.json" if resume else None

        with ProgressManager(enabled=progress) as pm:
            cb = create_progress_callback(pm)

            collector = RefreshHistoryCollector(
                auth=auth,
                inventory_result=inventory_result,
                progress_callback=cb,
                checkpoint_file=str(checkpoint_file) if checkpoint_file else None,
                history_limit=limit,
                progress_manager=pm if progress else None
            )

            result = collector.collect()

        exporter = FileExporter(format=format, output_dir=output, run_dir=run_dir)
        output_path = exporter.export(result, [])

        click.echo(f"\n✓ Refresh history exportado em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("COLETA CONCLUÍDA")
        click.echo("="*70)
        click.echo(f"Total de refreshes: {len(result['refresh_history'])}")
        click.echo(f"Erros: {len(result['refresh_history_errors'])}")
        click.echo("="*70)

    except CheckpointSavedException as e:
        click.echo("\n" + "="*70)
        click.echo("COLETA INTERROMPIDA")
        click.echo("="*70)
        click.echo(f"⏹️  {e.progress} artefatos processados")
        click.echo(f"💾 Checkpoint: {e.checkpoint_file}")
        click.echo(f"⏰ Aguarde ~1 hora e execute novamente")
        click.echo("="*70)
        _checkpoint_abort = True
        raise click.Abort()

    except Exception as e:
        _checkpoint_abort = False
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


# ── refresh-schedules ─────────────────────────────────────────────────────────

@collect.command('refresh-schedules')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--run-dir', default=None, hidden=True, help='Diretório de sessão fixo (usado pelo all)')
def refresh_schedules(format, output, run_dir):
    """
    Extrai agendamentos de refreshes do inventário (não faz chamadas à API)

    Exemplo:
        fabricgov collect refresh-schedules
    """
    global _checkpoint_abort
    click.echo("="*70)
    click.echo("COLETA DE SCHEDULES DE REFRESHES")
    click.echo("="*70)

    inventory_path = Path(output) / "inventory_result.json"
    if not inventory_path.exists():
        click.echo("❌ Erro: Execute 'fabricgov collect inventory' primeiro!", err=True)
        _checkpoint_abort = False
        raise click.Abort()

    with open(inventory_path, "r", encoding="utf-8") as f:
        inventory_result = json.load(f)

    try:
        auth = get_auth_provider()

        def _progress(msg: str):
            timestamp = datetime.now().strftime('%H:%M:%S')
            click.echo(f"[{timestamp}] {msg}")

        collector = RefreshScheduleCollector(
            auth=auth,
            inventory_result=inventory_result,
            progress_callback=_progress
        )

        result = collector.collect()

        exporter = FileExporter(format=format, output_dir=output, run_dir=run_dir)
        output_path = exporter.export(result, [])

        click.echo(f"\n✓ Refresh schedules exportado em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("COLETA CONCLUÍDA")
        click.echo("="*70)
        click.echo(f"Total de schedules: {len(result['refresh_schedules'])}")

        summary = result['summary']
        click.echo(f"Habilitados: {summary['schedules_enabled']}")
        click.echo(f"Desabilitados: {summary['schedules_disabled']}")
        click.echo("="*70)

    except Exception as e:
        _checkpoint_abort = False
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


# ── domains ───────────────────────────────────────────────────────────────────

@collect.command('domains')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--non-empty-only', is_flag=True, default=False, help='Apenas domínios com workspaces contendo itens')
@click.option('--run-dir', default=None, hidden=True, help='Diretório de sessão fixo (usado pelo all)')
def domains(format, output, non_empty_only, run_dir):
    """
    Coleta todos os domínios do tenant

    Exemplo:
        fabricgov collect domains
        fabricgov collect domains --non-empty-only
    """
    global _checkpoint_abort
    click.echo("="*70)
    click.echo("COLETA DE DOMÍNIOS")
    click.echo("="*70)

    try:
        auth = get_auth_provider()

        def _progress(msg: str):
            timestamp = datetime.now().strftime('%H:%M:%S')
            click.echo(f"[{timestamp}] {msg}")

        collector = DomainCollector(
            auth=auth,
            progress_callback=_progress,
            non_empty_only=non_empty_only,
        )

        result = collector.collect()

        exporter = FileExporter(format=format, output_dir=output, run_dir=run_dir)
        output_path = exporter.export(result, [])

        click.echo(f"\n✓ Domínios exportados em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("COLETA CONCLUÍDA")
        click.echo("="*70)
        summary = result['summary']
        click.echo(f"Total de domínios:      {summary['total_domains']}")
        click.echo(f"Domínios raiz:          {summary['root_domains']}")
        click.echo(f"Subdomínios:            {summary['sub_domains']}")
        click.echo(f"Com label padrão:       {summary['domains_with_default_label']}")
        click.echo("="*70)

    except Exception as e:
        _checkpoint_abort = False
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


# ── tags ──────────────────────────────────────────────────────────────────────

@collect.command('tags')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--run-dir', default=None, hidden=True, help='Diretório de sessão fixo (usado pelo all)')
def tags(format, output, run_dir):
    """
    Coleta todas as tags do tenant

    Exemplo:
        fabricgov collect tags
        fabricgov collect tags --format json
    """
    global _checkpoint_abort
    click.echo("="*70)
    click.echo("COLETA DE TAGS")
    click.echo("="*70)

    try:
        auth = get_auth_provider()

        def _progress(msg: str):
            timestamp = datetime.now().strftime('%H:%M:%S')
            click.echo(f"[{timestamp}] {msg}")

        collector = TagCollector(
            auth=auth,
            progress_callback=_progress,
        )

        result = collector.collect()

        exporter = FileExporter(format=format, output_dir=output, run_dir=run_dir)
        output_path = exporter.export(result, [])

        click.echo(f"\n✓ Tags exportadas em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("COLETA CONCLUÍDA")
        click.echo("="*70)
        summary = result['summary']
        click.echo(f"Total de tags:          {summary['total_tags']}")
        click.echo(f"Escopo Tenant:          {summary['tenant_tags']}")
        click.echo(f"Escopo Domain:          {summary['domain_tags']}")
        click.echo("="*70)

    except Exception as e:
        _checkpoint_abort = False
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


# ── capacities ────────────────────────────────────────────────────────────────

@collect.command('capacities')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--run-dir', default=None, hidden=True, help='Diretório de sessão fixo (usado pelo all)')
def capacities(format, output, run_dir):
    """
    Coleta todas as capacidades do tenant

    Exemplo:
        fabricgov collect capacities
        fabricgov collect capacities --format json
    """
    global _checkpoint_abort
    click.echo("="*70)
    click.echo("COLETA DE CAPACIDADES")
    click.echo("="*70)

    try:
        auth = get_auth_provider()

        def _progress(msg: str):
            timestamp = datetime.now().strftime('%H:%M:%S')
            click.echo(f"[{timestamp}] {msg}")

        collector = CapacityCollector(
            auth=auth,
            progress_callback=_progress,
        )

        result = collector.collect()

        exporter = FileExporter(format=format, output_dir=output, run_dir=run_dir)
        output_path = exporter.export(result, [])

        click.echo(f"\n✓ Capacidades exportadas em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("COLETA CONCLUÍDA")
        click.echo("="*70)
        summary = result['summary']
        click.echo(f"Total de capacidades:   {summary['total_capacities']}")
        click.echo(f"Ativas:                 {summary['active']}")
        click.echo(f"Suspensas:              {summary['suspended']}")
        if summary['skus']:
            click.echo(f"SKUs: {summary['skus']}")
        click.echo("="*70)

    except Exception as e:
        _checkpoint_abort = False
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


# ── workloads ─────────────────────────────────────────────────────────────────

@collect.command('workloads')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--run-dir', default=None, hidden=True, help='Diretório de sessão fixo (usado pelo all)')
def workloads(format, output, run_dir):
    """
    Coleta workloads de capacidades Gen1 (P-SKU, A-SKU)

    Busca as capacidades automaticamente e coleta os workloads de cada uma.
    Capacidades Fabric (F-SKU) são ignoradas automaticamente.

    Exemplo:
        fabricgov collect workloads
        fabricgov collect workloads --format json
    """
    global _checkpoint_abort
    click.echo("="*70)
    click.echo("COLETA DE WORKLOADS")
    click.echo("="*70)

    try:
        auth = get_auth_provider()

        def _progress(msg: str):
            timestamp = datetime.now().strftime('%H:%M:%S')
            click.echo(f"[{timestamp}] {msg}")

        _progress("Buscando capacidades do tenant...")
        capacity_collector = CapacityCollector(auth=auth)
        capacities_result = capacity_collector.collect()
        _progress(f"  {capacities_result['summary']['total_capacities']} capacidades encontradas")

        collector = WorkloadCollector(
            auth=auth,
            capacities_result=capacities_result,
            progress_callback=_progress,
        )

        result = collector.collect()

        exporter = FileExporter(format=format, output_dir=output, run_dir=run_dir)
        output_path = exporter.export(result, [])

        click.echo(f"\n✓ Workloads exportados em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("COLETA CONCLUÍDA")
        click.echo("="*70)
        summary = result['summary']
        click.echo(f"Capacidades processadas: {summary['capacities_processed']}")
        click.echo(f"Ignoradas (Gen2):        {summary['capacities_skipped_gen2']}")
        click.echo(f"Total de workloads:      {summary['total_workloads']}")
        click.echo(f"Habilitados:             {summary['enabled']}")
        click.echo(f"Desabilitados:           {summary['disabled']}")
        if summary['errors']:
            click.echo(f"Erros:                   {summary['errors']}")
        click.echo("="*70)

    except Exception as e:
        _checkpoint_abort = False
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


# ── activity ──────────────────────────────────────────────────────────────────

@collect.command('activity')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--days', default=7, show_default=True, help='Número de dias de histórico (máximo 28)')
@click.option('--filter-activity', default=None, help='Filtrar por tipo de atividade (ex: ViewReport)')
@click.option('--filter-user', default=None, help='Filtrar por email do usuário')
@click.option('--run-dir', default=None, hidden=True, help='Diretório de sessão fixo (usado pelo all)')
def activity(format, output, days, filter_activity, filter_user, run_dir):
    """
    Coleta eventos de atividade do tenant (últimos N dias)

    Limites da API:
      - Histórico máximo: 28 dias
      - Janela por request: 1 dia UTC
      - Rate limit: 200 req/hora (compartilhado)

    Exemplos:
        fabricgov collect activity
        fabricgov collect activity --days 28
        fabricgov collect activity --days 3 --filter-activity ViewReport
        fabricgov collect activity --days 1 --filter-user user@empresa.com
    """
    global _checkpoint_abort
    click.echo("="*70)
    click.echo("COLETA DE EVENTOS DE ATIVIDADE")
    click.echo("="*70)

    try:
        auth = get_auth_provider()

        def _progress(msg: str):
            timestamp = datetime.now().strftime('%H:%M:%S')
            click.echo(f"[{timestamp}] {msg}")

        collector = ActivityCollector(
            auth=auth,
            days=days,
            filter_activity=filter_activity,
            filter_user=filter_user,
            progress_callback=_progress,
        )

        result = collector.collect()

        exporter = FileExporter(format=format, output_dir=output, run_dir=run_dir)
        output_path = exporter.export(result, [])

        click.echo(f"\n✓ Eventos exportados em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("COLETA CONCLUÍDA")
        click.echo("="*70)
        summary = result['summary']
        click.echo(f"Total de eventos:       {summary['total_events']}")
        click.echo(f"Dias coletados:         {summary['days_collected']}/{summary['days_requested']}")
        click.echo(f"Usuários únicos:        {summary['unique_users']}")
        click.echo(f"Tipos de atividade:     {summary['unique_activity_types']}")
        if summary['days_with_errors']:
            click.echo(f"Dias com erro:          {summary['days_with_errors']}")
        if summary['top_activities']:
            click.echo("\nTop atividades:")
            for act in summary['top_activities'][:5]:
                click.echo(f"  {act['activity']:<35} {act['count']:>6}")
        click.echo("="*70)

    except Exception as e:
        _checkpoint_abort = False
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


# ── all-infrastructure ────────────────────────────────────────────────────────

@collect.command('all-infrastructure')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--run-dir', default=None, hidden=True, help='Diretório de sessão fixo (usado pelo all)')
def all_infrastructure(format, output, run_dir):
    """
    Coleta TODA a infraestrutura do tenant (domains, tags, capacities, workloads)

    Executa em sequência:
    1. domains
    2. tags
    3. capacities
    4. workloads

    Exemplo:
        fabricgov collect all-infrastructure
        fabricgov collect all-infrastructure --format json
    """
    click.echo("="*70)
    click.echo("COLETA DE INFRAESTRUTURA DO TENANT")
    click.echo("="*70)
    click.echo()

    ctx = click.get_current_context()

    steps = [
        (domains,     "Domínios"),
        (tags,        "Tags"),
        (capacities,  "Capacidades"),
        (workloads,   "Workloads"),
    ]

    for fn, label in steps:
        click.echo(f"▶️  Iniciando coleta: {label}")
        click.echo("-"*70)
        ctx.invoke(fn, format=format, output=output, run_dir=run_dir)
        click.echo()

    click.echo("="*70)
    click.echo("✅ INFRAESTRUTURA COLETADA")
    click.echo("="*70)


# ── all-access ────────────────────────────────────────────────────────────────

@collect.command('all-access')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--resume/--no-resume', default=True, help='Retomar de checkpoint')
@click.option('--progress/--no-progress', default=True, help='Mostrar progress bars')
@click.option('--run-dir', default=None, hidden=True, help='Diretório de sessão fixo (usado pelo all)')
def all_access(format, output, resume, progress, run_dir):
    """
    Coleta TODOS os acessos (workspace, report, dataset, dataflow)

    Executa todos os collectors de acesso em sequência.
    Se algum bater rate limit, para e instrui a retomar.

    Exemplo:
        fabricgov collect all-access
    """
    click.echo("="*70)
    click.echo("COLETA DE TODOS OS ACESSOS")
    click.echo("="*70)
    click.echo()

    collectors_to_run = [
        ('workspace-access', 'Workspaces', 'checkpoint_workspace_access.json'),
    ]

    ctx = click.get_current_context()
    for cmd_name, label, ckpt_name in collectors_to_run:
        session_dir = Path(run_dir) if run_dir else Path(output)
        root_ckpt = Path(output) / ckpt_name  # checkpoints ficam na raiz do output/

        # Se resume=True e o CSV já existe na pasta da sessão,
        # este coletor completou em execução anterior — pula e limpa checkpoint stale.
        csv_name = cmd_name.replace('-', '_') + ".csv"
        csv_done = (session_dir / csv_name).exists()
        if resume and csv_done:
            if root_ckpt.exists():
                root_ckpt.unlink()  # remove checkpoint stale
            click.echo(f"⏭️  {label}: já concluído, pulando.")
            click.echo()
            continue

        click.echo(f"▶️  Iniciando coleta: {label}")
        click.echo("-"*70)

        ctx.invoke(
            globals()[cmd_name.replace('-', '_')],
            format=format,
            output=output,
            resume=resume,
            progress=progress,
            run_dir=run_dir,
        )

        click.echo()

    click.echo("="*70)
    click.echo("✅ TODAS AS COLETAS CONCLUÍDAS")
    click.echo("="*70)


# ── all-refresh ───────────────────────────────────────────────────────────────

@collect.command('all-refresh')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--resume/--no-resume', default=True, help='Retomar de checkpoint')
@click.option('--limit', default=100, help='Número máximo de refreshes por artefato (history)')
@click.option('--progress/--no-progress', default=True, help='Mostrar progress bars')
@click.option('--run-dir', default=None, hidden=True, help='Diretório de sessão fixo (usado pelo all)')
def all_refresh(format, output, resume, limit, progress, run_dir):
    """
    Coleta TODOS os dados de refresh (history + schedules)

    Executa:
    1. refresh-history (com checkpoint)
    2. refresh-schedules (rápido, sem API)

    Exemplo:
        fabricgov collect all-refresh
        fabricgov collect all-refresh --limit 50
    """
    click.echo("="*70)
    click.echo("COLETA COMPLETA DE REFRESH DATA")
    click.echo("="*70)
    click.echo()

    ctx = click.get_current_context()

    click.echo(f"▶️  Iniciando coleta: Refresh History")
    click.echo("-"*70)

    ctx.invoke(
        refresh_history,
        format=format,
        output=output,
        resume=resume,
        limit=limit,
        progress=progress,
        run_dir=run_dir,
    )

    click.echo()

    click.echo(f"▶️  Iniciando coleta: Refresh Schedules")
    click.echo("-"*70)

    ctx.invoke(
        refresh_schedules,
        format=format,
        output=output,
        run_dir=run_dir,
    )

    click.echo()
    click.echo("="*70)
    click.echo("✅ COLETA DE REFRESH DATA CONCLUÍDA")
    click.echo("="*70)


# ── status ────────────────────────────────────────────────────────────────────

@collect.command('status')
@click.option('--output', default='output', help='Diretório de output')
def status(output):
    """
    Mostra o status da sessão de coleta atual e checkpoints pendentes.

    Exemplo:
        fabricgov collect status
        fabricgov collect status --output meu_output
    """
    SEP = "═" * 70
    session = load_session(output)
    pending = find_pending_checkpoints(output)

    click.echo(SEP)
    click.echo("STATUS DA SESSÃO DE COLETA")
    click.echo(SEP)

    if session:
        run_dir = session.get("run_dir", "—")
        started = session.get("started_at", "—")
        steps = session.get("steps", {})

        # Determina status geral
        statuses = [s.get("status", "not_started") for s in steps.values()]
        if all(s == "completed" for s in statuses):
            overall = "CONCLUÍDA"
        elif any(s == "checkpointed" for s in statuses):
            overall = "INTERROMPIDA (checkpoint pendente)"
        elif any(s == "failed" for s in statuses):
            overall = "COM ERRO"
        else:
            overall = "EM ANDAMENTO"

        click.echo(f"Pasta:      {run_dir}")
        click.echo(f"Iniciada:   {started}")
        click.echo(f"Status:     {overall}")
        click.echo()
        click.echo("Passos:")

        icons = {
            "completed":   "✅",
            "checkpointed": "⏹️ ",
            "failed":      "❌",
            "not_started": "⏳",
        }
        labels = {
            "inventory":          "inventory          ",
            "all-infrastructure": "all-infrastructure ",
            "all-access":         "all-access         ",
            "all-refresh":        "all-refresh        ",
            "activity":           "activity           ",
        }

        for step in ["inventory", "all-infrastructure", "all-access", "all-refresh", "activity"]:
            info = steps.get(step, {})
            st = info.get("status", "not_started")
            icon = icons.get(st, "⏳")
            label = labels.get(step, step)
            detail = ""
            if st == "completed":
                detail = f"concluído {info.get('completed_at', '')}"
            elif st == "checkpointed":
                detail = f"interrompido {info.get('checkpointed_at', '')}"
            elif st == "failed":
                detail = f"erro: {info.get('error', '')}"
            click.echo(f"  {icon} {label} {detail}")
    else:
        click.echo("Nenhuma sessão ativa encontrada.")

    if pending:
        click.echo()
        click.echo("Checkpoints detectados:")
        for cp in pending:
            click.echo(f"  💾 {cp}")

    if session or pending:
        click.echo()
        click.echo("Para retomar: fabricgov collect all --resume")
    else:
        click.echo()
        click.echo("✅ Nenhuma sessão ativa. Nenhum checkpoint pendente.")

    click.echo(SEP)


# ── all ───────────────────────────────────────────────────────────────────────

@collect.command('all')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--resume/--no-resume', default=True, help='Retomar sessão anterior se existir')
@click.option('--limit', default=100, help='Número máximo de refreshes por artefato (history)')
@click.option('--progress/--no-progress', default=True, help='Mostrar progress bars')
@click.option('--days', default=28, show_default=True, help='Dias de histórico de atividades (0 = pular activity)')
def all_collect(format, output, resume, limit, progress, days):
    """
    Coleta TUDO em uma única sessão (inventory → infrastructure → access → refresh → activity).

    Usa uma pasta única para todos os outputs. Se algum passo bater rate limit,
    salva o checkpoint e continua para o próximo passo. Execute novamente com
    --resume para completar os passos interrompidos.

    Exemplo:
        fabricgov collect all
        fabricgov collect all --resume
        fabricgov collect all --no-resume    # inicia sessão do zero
        fabricgov collect all --limit 50
        fabricgov collect all --days 7       # apenas últimos 7 dias de atividade
        fabricgov collect all --days 0       # pula coleta de atividades
    """
    global _checkpoint_abort

    click.echo("=" * 70)
    click.echo("COLETA COMPLETA DO TENANT")
    click.echo("=" * 70)

    # ── Carrega ou cria sessão ────────────────────────────────────────────────
    existing = load_session(output) if resume else None

    if existing and resume:
        session = existing
        run_dir = session["run_dir"]
        click.echo(f"▶️  Retomando sessão: {run_dir}")
    else:
        session = create_new_session(output, format)
        run_dir = session["run_dir"]
        save_session(output, session)
        click.echo(f"▶️  Nova sessão: {run_dir}")

    click.echo()
    ctx = click.get_current_context()

    # Se days == 0, marca "activity" como concluído para não bloquear is_session_complete
    if days == 0 and get_step_status(session, "activity") == "not_started":
        mark_step_completed(session, "activity")
        save_session(output, session)

    # ── Passo 1: inventory (crítico) ──────────────────────────────────────────
    step = "inventory"
    if get_step_status(session, step) == "completed":
        click.echo(f"⏭️  {step}: já concluído, pulando.")
    else:
        click.echo(f"{'='*70}")
        click.echo(f"▶️  PASSO 1: INVENTORY")
        click.echo(f"{'='*70}")
        _checkpoint_abort = False
        try:
            ctx.invoke(
                inventory,
                format=format,
                output=output,
                progress=progress,
                run_dir=run_dir,
            )
            mark_step_completed(session, step)
            save_session(output, session)
        except click.Abort:
            mark_step_failed(session, step)
            save_session(output, session)
            click.echo("\n❌ Inventory falhou. Não é possível continuar sem o inventário.")
            raise

    click.echo()

    # ── Passo 2: all-infrastructure (independente, rápido) ───────────────────
    step = "all-infrastructure"
    if get_step_status(session, step) == "completed":
        click.echo(f"⏭️  {step}: já concluído, pulando.")
    else:
        click.echo(f"{'='*70}")
        click.echo(f"▶️  PASSO 2: INFRAESTRUTURA")
        click.echo(f"{'='*70}")
        _checkpoint_abort = False
        try:
            ctx.invoke(
                all_infrastructure,
                format=format,
                output=output,
                run_dir=run_dir,
            )
            mark_step_completed(session, step)
            save_session(output, session)
        except click.Abort:
            mark_step_failed(session, step, "erro durante coleta de infraestrutura")
            save_session(output, session)
            click.echo("\n⚠️  Infraestrutura falhou, continuando com os próximos passos...")

    click.echo()

    # ── Passo 3: all-access (pode checkpointar) ───────────────────────────────
    step = "all-access"
    step_status = get_step_status(session, step)
    if step_status == "completed":
        click.echo(f"⏭️  {step}: já concluído, pulando.")
    else:
        click.echo(f"{'='*70}")
        click.echo(f"▶️  PASSO 3: ACESSOS")
        click.echo(f"{'='*70}")
        _checkpoint_abort = False
        # Sempre passa o --resume do usuário: o collector só retoma se o arquivo existir
        inner_resume = resume
        try:
            ctx.invoke(
                all_access,
                format=format,
                output=output,
                resume=inner_resume,
                progress=progress,
                run_dir=run_dir,
            )
            mark_step_completed(session, step)
            save_session(output, session)
        except click.Abort:
            if _checkpoint_abort:
                _checkpoint_abort = False
                mark_step_checkpointed(session, step)
                save_session(output, session)
                click.echo("\n⏩  all-access interrompido por rate limit. Continuando para all-refresh...")
            else:
                mark_step_failed(session, step, "erro inesperado")
                save_session(output, session)
                click.echo("\n⚠️  all-access falhou com erro. Continuando para all-refresh...")

    click.echo()

    # ── Passo 4: all-refresh (pode checkpointar) ──────────────────────────────
    step = "all-refresh"
    step_status = get_step_status(session, step)
    if step_status == "completed":
        click.echo(f"⏭️  {step}: já concluído, pulando.")
    else:
        click.echo(f"{'='*70}")
        click.echo(f"▶️  PASSO 4: REFRESH")
        click.echo(f"{'='*70}")
        _checkpoint_abort = False
        inner_resume = resume
        try:
            ctx.invoke(
                all_refresh,
                format=format,
                output=output,
                resume=inner_resume,
                limit=limit,
                progress=progress,
                run_dir=run_dir,
            )
            mark_step_completed(session, step)
            save_session(output, session)
        except click.Abort:
            if _checkpoint_abort:
                _checkpoint_abort = False
                mark_step_checkpointed(session, step)
                save_session(output, session)
                click.echo("\n⏩  all-refresh interrompido por rate limit.")
            else:
                mark_step_failed(session, step, "erro inesperado")
                save_session(output, session)
                click.echo("\n⚠️  all-refresh falhou com erro.")

    click.echo()

    # ── Passo 5: activity (opcional, padrão 28 dias) ───────────────────────────
    if days > 0:
        step = "activity"
        if get_step_status(session, step) == "completed":
            click.echo(f"⏭️  {step}: já concluído, pulando.")
        else:
            click.echo(f"{'='*70}")
            click.echo(f"▶️  PASSO 5: ATIVIDADES ({days} dias)")
            click.echo(f"{'='*70}")
            _checkpoint_abort = False
            try:
                ctx.invoke(
                    activity,
                    format=format,
                    output=output,
                    days=days,
                    filter_activity=None,
                    filter_user=None,
                    run_dir=run_dir,
                )
                mark_step_completed(session, step)
                save_session(output, session)
            except click.Abort:
                mark_step_failed(session, step, "erro durante coleta de atividades")
                save_session(output, session)
                click.echo("\n⚠️  Coleta de atividades falhou, sessão continua.")

        click.echo()

    # ── Resumo final ──────────────────────────────────────────────────────────
    click.echo("=" * 70)
    click.echo("RESUMO DA SESSÃO")
    click.echo("=" * 70)
    click.echo(f"Pasta: {run_dir}")
    click.echo()

    all_steps = ["inventory", "all-infrastructure", "all-access", "all-refresh"]
    if days > 0:
        all_steps.append("activity")

    has_pending = False
    for s in all_steps:
        st = get_step_status(session, s)
        if st == "completed":
            icon = "✅"
        elif st == "checkpointed":
            icon = "⏹️ "
            has_pending = True
        elif st == "failed":
            icon = "❌"
            has_pending = True
        else:
            icon = "⏳"
            has_pending = True
        click.echo(f"  {icon} {s}")

    click.echo()

    if is_session_complete(session):
        click.echo("✅ COLETA COMPLETA CONCLUÍDA!")
        clear_session(output)
    else:
        click.echo("⏹️  Sessão incompleta.")
        pending = find_pending_checkpoints(output)
        if pending:
            click.echo("Checkpoints pendentes:")
            for cp in pending:
                ckpt_path = Path(output) / cp
                progress_str = ""
                cycles_str = ""
                try:
                    with open(ckpt_path, encoding="utf-8") as f:
                        ckpt = json.load(f)
                    prog = ckpt.get("progress", "")
                    if "/" in prog:
                        done, total = prog.split("/")
                        done, total = int(done), int(total)
                        remaining = total - done
                        # ~200 req/hora por ciclo
                        cycles = max(1, -(-remaining // 200))
                        progress_str = f"{done}/{total}"
                        cycles_str = f" → ~{cycles} ciclo(s) restante(s)"
                except Exception:
                    pass
                label = f"  💾 {cp}"
                if progress_str:
                    label += f"  ({progress_str}{cycles_str})"
                click.echo(label)
        click.echo()
        click.echo("Execute novamente para retomar: fabricgov collect all --resume")

    click.echo("=" * 70)


# ── auth provider ─────────────────────────────────────────────────────────────

def get_auth_provider():
    """
    Retorna o AuthProvider baseado na última autenticação utilizada.

    Raises:
        RuntimeError: Se nenhuma autenticação foi configurada
    """
    require_auth()  # Valida se já autenticou

    method = get_auth_preference()

    if method == "service_principal":
        return ServicePrincipalAuth.from_env()
    elif method == "device_flow":
        return DeviceFlowAuth()
    elif method == "keyvault":
        kv_config = get_keyvault_config()
        if not kv_config:
            raise RuntimeError(
                "❌ Configuração do Key Vault não encontrada!\n"
                "   Execute 'fabricgov auth keyvault --vault-url <url>' novamente."
            )
        return KeyVaultAuth(
            vault_url=kv_config["vault_url"],
            secret_names=kv_config["secret_names"],
        ).to_service_principal()
    else:
        raise RuntimeError(
            "❌ Método de autenticação inválido!\n"
            "   Execute 'fabricgov auth clear' e autentique novamente"
        )
