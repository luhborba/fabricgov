import click
from fabricgov.cli.auth import auth
from fabricgov.cli.collect import collect


@click.group()
@click.version_option(version="0.3.0", prog_name="fabricgov")
def cli():
    """
    fabricgov - Biblioteca Python para assessment automatizado de governança em Microsoft Fabric
    
    Comandos disponíveis:
    
      auth     - Comandos de autenticação
      collect  - Comandos de coleta de dados
    
    Exemplos:
    
      # Testa credenciais
      fabricgov auth test
      
      # Coleta inventário
      fabricgov collect inventory
      
      # Coleta acessos de workspaces
      fabricgov collect workspace-access
      
      # Coleta todos os acessos
      fabricgov collect all-access
    """
    pass


# Registra subcomandos
cli.add_command(auth)
cli.add_command(collect)


if __name__ == "__main__":
    cli()