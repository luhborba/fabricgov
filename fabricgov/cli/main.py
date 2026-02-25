import click
from fabricgov.cli.auth import auth
from fabricgov.cli.collect import collect

__version__ = "0.3.3"


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
    
    \b
    📖 Documentação: https://github.com/luhborba/fabricgov
    """
    pass


cli.add_command(auth)
cli.add_command(collect)


if __name__ == '__main__':
    cli()