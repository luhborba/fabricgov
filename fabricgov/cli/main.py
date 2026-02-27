import click
from fabricgov.cli.auth import auth
from fabricgov.cli.collect import collect
from fabricgov.cli.report import report_cmd

__version__ = "0.7.0"


@click.group()
@click.version_option(version=__version__, prog_name="fabricgov")
def cli():
    """
    fabricgov - Assessment automatizado de governança em Microsoft Fabric

    \b
    🔐 Autenticação:
      fabricgov auth sp       # Service Principal (.env)
      fabricgov auth device   # Device Flow (interativo)
      fabricgov auth clear    # Limpa autenticação

    \b
    📊 Coleta de Dados:
      fabricgov collect inventory          # Inventário completo
      fabricgov collect workspace-access   # Roles em workspaces
      fabricgov collect report-access      # Permissões em reports
      fabricgov collect dataset-access     # Permissões em datasets
      fabricgov collect dataflow-access    # Permissões em dataflows
      fabricgov collect refresh-history    # Histórico de refreshes
      fabricgov collect refresh-schedules  # Agendamentos configurados

    \b
    ⚡ Atalhos:
      fabricgov collect all-access   # Todos os access collectors
      fabricgov collect all-refresh  # Refresh history + schedules
      fabricgov collect all          # Coleta completa em sessão única

    \b
    📊 Relatório:
      fabricgov report                     # Gera HTML do run mais recente
      fabricgov report --from output/...   # Pasta específica
      fabricgov report --open              # Abre no browser após gerar

    \b
    📖 Documentação: https://github.com/luhborba/fabricgov
    """
    pass


cli.add_command(auth)
cli.add_command(collect)
cli.add_command(report_cmd, name="report")


if __name__ == '__main__':
    cli()