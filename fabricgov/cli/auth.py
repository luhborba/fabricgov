import click
from fabricgov.auth import ServicePrincipalAuth, DeviceFlowAuth
from fabricgov.exceptions import AuthenticationError


@click.group()
def auth():
    """Comandos de autenticação"""
    pass


@auth.command()
def test():
    """
    Testa credenciais do Service Principal configuradas no .env
    
    Exemplo:
        fabricgov auth test
    """
    click.echo("🔐 Testando credenciais...")
    
    try:
        auth = ServicePrincipalAuth.from_env()
        token = auth.get_token("https://analysis.windows.net/powerbi/api/.default")
        
        click.echo("✅ Autenticação bem-sucedida!")
        click.echo(f"   Token obtido: {token[:50]}...")
        
    except AuthenticationError as e:
        click.echo(f"❌ Falha na autenticação: {e}", err=True)
        raise click.Abort()
    except Exception as e:
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


@auth.command()
def device():
    """
    Inicia autenticação interativa via Device Flow
    
    Exemplo:
        fabricgov auth device
    """
    click.echo("🔐 Iniciando Device Flow...")
    click.echo("   Você será redirecionado para autenticação no browser")
    click.echo()
    
    try:
        auth = DeviceFlowAuth()
        token = auth.get_token("https://analysis.windows.net/powerbi/api/.default")
        
        click.echo()
        click.echo("✅ Autenticação bem-sucedida!")
        click.echo(f"   Token obtido: {token[:50]}...")
        click.echo("   Token salvo em cache para próximas execuções")
        
    except AuthenticationError as e:
        click.echo(f"❌ Falha na autenticação: {e}", err=True)
        raise click.Abort()
    except Exception as e:
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()