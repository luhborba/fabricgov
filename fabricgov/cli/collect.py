import click
import json
from pathlib import Path
from datetime import datetime
from fabricgov.auth import ServicePrincipalAuth, DeviceFlowAuth
from fabricgov.collectors import (
    WorkspaceInventoryCollector,
    WorkspaceAccessCollector,
    ReportAccessCollector,
    DatasetAccessCollector,
    DataflowAccessCollector,
)
from fabricgov.exporters import FileExporter
from fabricgov.exceptions import CheckpointSavedException
from fabricgov.config import get_auth_preference, require_auth  
from fabricgov.progress import ProgressManager, create_progress_callback


@click.group()
def collect():
    """Comandos de coleta de dados"""
    pass

def progress_callback(msg: str):
    """Callback para exibir progresso"""
    timestamp = datetime.now().strftime('%H:%M:%S')
    click.echo(f"[{timestamp}] {msg}")


@collect.command()
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--progress/--no-progress', default=True, help='Mostrar progress bars')
def inventory(format, output, progress):
    """
    Coleta inventário completo de workspaces e artefatos
    
    Exemplo:
        fabricgov collect inventory
        fabricgov collect inventory --no-progress
    """
    click.echo("="*70)
    click.echo("COLETA DE INVENTÁRIO")
    click.echo("="*70)
    
    try:
        auth = get_auth_provider()
        
        with ProgressManager(enabled=progress) as pm:
            progress_callback = create_progress_callback(pm)
            
            collector = WorkspaceInventoryCollector(
                auth=auth,
                progress_callback=progress_callback,
                progress_manager=pm if progress else None  
            )
            result = collector.collect()
        
        # Salva inventory_result.json
        inventory_path = Path(output) / "inventory_result.json"
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        with open(inventory_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        click.echo(f"\n✓ Inventário salvo em: {inventory_path}")
        
        # Exporta em CSV/JSON
        exporter = FileExporter(format=format, output_dir=output)
        output_path = exporter.export(result, [])
        
        click.echo(f"✓ Arquivos exportados em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("INVENTÁRIO CONCLUÍDO")
        click.echo("="*70)
        click.echo(f"Total de workspaces: {result['summary']['total_workspaces']}")
        click.echo(f"Total de itens: {result['summary']['total_items']}")
        click.echo("="*70)
        
    except Exception as e:
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


@collect.command('workspace-access')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--resume/--no-resume', default=True, help='Retomar de checkpoint')
def workspace_access(format, output, resume):
    """
    Coleta roles de acesso em workspaces
    
    Exemplo:
        fabricgov collect workspace-access
        fabricgov collect workspace-access --no-resume
    """
    click.echo("="*70)
    click.echo("COLETA DE ACESSOS EM WORKSPACES")
    click.echo("="*70)
    
    # Carrega inventário
    inventory_path = Path(output) / "inventory_result.json"
    if not inventory_path.exists():
        click.echo("❌ Erro: Execute 'fabricgov collect inventory' primeiro!", err=True)
        raise click.Abort()
    
    with open(inventory_path, "r", encoding="utf-8") as f:
        inventory_result = json.load(f)
    
    try:
        auth = get_auth_provider()
        
        checkpoint_file = Path(output) / "checkpoint_workspace_access.json" if resume else None
        
        collector = WorkspaceAccessCollector(
            auth=auth,
            inventory_result=inventory_result,
            progress_callback=progress_callback,
            checkpoint_file=str(checkpoint_file) if checkpoint_file else None
        )
        
        result = collector.collect()
        
        # Exporta resultado
        exporter = FileExporter(format=format, output_dir=output)
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
        raise click.Abort()
    
    except Exception as e:
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


@collect.command('report-access')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--resume/--no-resume', default=True, help='Retomar de checkpoint')
def report_access(format, output, resume):
    """
    Coleta permissões de acesso em reports
    
    Exemplo:
        fabricgov collect report-access
    """
    click.echo("="*70)
    click.echo("COLETA DE ACESSOS EM REPORTS")
    click.echo("="*70)
    
    inventory_path = Path(output) / "inventory_result.json"
    if not inventory_path.exists():
        click.echo("❌ Erro: Execute 'fabricgov collect inventory' primeiro!", err=True)
        raise click.Abort()
    
    with open(inventory_path, "r", encoding="utf-8") as f:
        inventory_result = json.load(f)
    
    try:
        auth = get_auth_provider()
        
        checkpoint_file = Path(output) / "checkpoint_report_access.json" if resume else None
        
        collector = ReportAccessCollector(
            auth=auth,
            inventory_result=inventory_result,
            progress_callback=progress_callback,
            checkpoint_file=str(checkpoint_file) if checkpoint_file else None
        )
        
        result = collector.collect()
        
        exporter = FileExporter(format=format, output_dir=output)
        output_path = exporter.export(result, [])
        
        click.echo(f"\n✓ Report access exportado em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("COLETA CONCLUÍDA")
        click.echo("="*70)
        click.echo(f"Total de acessos: {len(result['report_access'])}")
        click.echo(f"Erros: {len(result['report_access_errors'])}")
        click.echo("="*70)
        
    except CheckpointSavedException as e:
        click.echo("\n" + "="*70)
        click.echo("COLETA INTERROMPIDA")
        click.echo("="*70)
        click.echo(f"⏹️  {e.progress} reports processados")
        click.echo(f"💾 Checkpoint: {e.checkpoint_file}")
        click.echo(f"⏰ Aguarde ~1 hora e execute novamente")
        click.echo("="*70)
        raise click.Abort()
    
    except Exception as e:
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


@collect.command('dataset-access')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--resume/--no-resume', default=True, help='Retomar de checkpoint')
def dataset_access(format, output, resume):
    """
    Coleta permissões de acesso em datasets
    
    Exemplo:
        fabricgov collect dataset-access
    """
    click.echo("="*70)
    click.echo("COLETA DE ACESSOS EM DATASETS")
    click.echo("="*70)
    
    inventory_path = Path(output) / "inventory_result.json"
    if not inventory_path.exists():
        click.echo("❌ Erro: Execute 'fabricgov collect inventory' primeiro!", err=True)
        raise click.Abort()
    
    with open(inventory_path, "r", encoding="utf-8") as f:
        inventory_result = json.load(f)
    
    try:
        auth = get_auth_provider()
        
        checkpoint_file = Path(output) / "checkpoint_dataset_access.json" if resume else None
        
        collector = DatasetAccessCollector(
            auth=auth,
            inventory_result=inventory_result,
            progress_callback=progress_callback,
            checkpoint_file=str(checkpoint_file) if checkpoint_file else None
        )
        
        result = collector.collect()
        
        exporter = FileExporter(format=format, output_dir=output)
        output_path = exporter.export(result, [])
        
        click.echo(f"\n✓ Dataset access exportado em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("COLETA CONCLUÍDA")
        click.echo("="*70)
        click.echo(f"Total de acessos: {len(result['dataset_access'])}")
        click.echo(f"Erros: {len(result['dataset_access_errors'])}")
        click.echo("="*70)
        
    except CheckpointSavedException as e:
        click.echo("\n" + "="*70)
        click.echo("COLETA INTERROMPIDA")
        click.echo("="*70)
        click.echo(f"⏹️  {e.progress} datasets processados")
        click.echo(f"💾 Checkpoint: {e.checkpoint_file}")
        click.echo(f"⏰ Aguarde ~1 hora e execute novamente")
        click.echo("="*70)
        raise click.Abort()
    
    except Exception as e:
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


@collect.command('dataflow-access')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--resume/--no-resume', default=True, help='Retomar de checkpoint')
def dataflow_access(format, output, resume):
    """
    Coleta permissões de acesso em dataflows
    
    Exemplo:
        fabricgov collect dataflow-access
    """
    click.echo("="*70)
    click.echo("COLETA DE ACESSOS EM DATAFLOWS")
    click.echo("="*70)
    
    inventory_path = Path(output) / "inventory_result.json"
    if not inventory_path.exists():
        click.echo("❌ Erro: Execute 'fabricgov collect inventory' primeiro!", err=True)
        raise click.Abort()
    
    with open(inventory_path, "r", encoding="utf-8") as f:
        inventory_result = json.load(f)
    
    try:
        auth = get_auth_provider()
        
        checkpoint_file = Path(output) / "checkpoint_dataflow_access.json" if resume else None
        
        collector = DataflowAccessCollector(
            auth=auth,
            inventory_result=inventory_result,
            progress_callback=progress_callback,
            checkpoint_file=str(checkpoint_file) if checkpoint_file else None
        )
        
        result = collector.collect()
        
        exporter = FileExporter(format=format, output_dir=output)
        output_path = exporter.export(result, [])
        
        click.echo(f"\n✓ Dataflow access exportado em: {output_path}")
        click.echo("\n" + "="*70)
        click.echo("COLETA CONCLUÍDA")
        click.echo("="*70)
        click.echo(f"Total de acessos: {len(result['dataflow_access'])}")
        click.echo(f"Erros: {len(result['dataflow_access_errors'])}")
        click.echo("="*70)
        
    except CheckpointSavedException as e:
        click.echo("\n" + "="*70)
        click.echo("COLETA INTERROMPIDA")
        click.echo("="*70)
        click.echo(f"⏹️  {e.progress} dataflows processados")
        click.echo(f"💾 Checkpoint: {e.checkpoint_file}")
        click.echo(f"⏰ Aguarde ~1 hora e execute novamente")
        click.echo("="*70)
        raise click.Abort()
    
    except Exception as e:
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


@collect.command('all-access')
@click.option('--format', type=click.Choice(['json', 'csv']), default='csv', help='Formato de export')
@click.option('--output', default='output', help='Diretório de output')
@click.option('--resume/--no-resume', default=True, help='Retomar de checkpoint')
def all_access(format, output, resume):
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
        ('workspace-access', 'Workspaces'),
        ('report-access', 'Reports'),
        ('dataset-access', 'Datasets'),
        ('dataflow-access', 'Dataflows'),
    ]
    
    for cmd_name, label in collectors_to_run:
        click.echo(f"▶️  Iniciando coleta: {label}")
        click.echo("-"*70)
        
        # Invoca o comando correspondente
        ctx = click.get_current_context()
        ctx.invoke(
            globals()[cmd_name.replace('-', '_')],
            format=format,
            output=output,
            resume=resume
        )
        
        click.echo()
    
    click.echo("="*70)
    click.echo("✅ TODAS AS COLETAS CONCLUÍDAS")
    click.echo("="*70)

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
    else:
        raise RuntimeError(
            "❌ Método de autenticação inválido!\n"
            "   Execute 'fabricgov auth clear' e autentique novamente"
        )