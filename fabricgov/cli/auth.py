import click
from fabricgov.auth import ServicePrincipalAuth, DeviceFlowAuth
from fabricgov.exceptions import AuthenticationError
from fabricgov.config import save_auth_preference, clear_auth_preference


@click.group()
def auth():
    """Comandos de autenticação"""
    pass


@auth.command()
def sp():
    """
    Testa credenciais do Service Principal (.env)
    
    Lê credenciais de FABRICGOV_TENANT_ID, FABRICGOV_CLIENT_ID
    e FABRICGOV_CLIENT_SECRET do arquivo .env
    
    Exemplo:
        fabricgov auth sp
    """
    click.echo("🔐 Testando Service Principal...")
    
    try:
        auth = ServicePrincipalAuth.from_env()
        token = auth.get_token("https://analysis.windows.net/powerbi/api/.default")
        
        click.echo("✅ Autenticação bem-sucedida!")
        click.echo(f"   Token obtido: {token[:50]}...")
        
        # Salva preferência
        save_auth_preference("service_principal")
        click.echo("   Método salvo: Service Principal")
        
    except AuthenticationError as e:
        click.echo(f"❌ Falha na autenticação: {e}", err=True)
        raise click.Abort()
    except Exception as e:
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


@auth.command()
def device():
    """
    Autenticação interativa via Device Flow
    
    Abre o browser para autenticação com sua conta Microsoft.
    Suporta MFA automaticamente.
    
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
        
        # Salva preferência
        save_auth_preference("device_flow")
        click.echo("   Método salvo: Device Flow")
        
    except AuthenticationError as e:
        click.echo(f"❌ Falha na autenticação: {e}", err=True)
        raise click.Abort()
    except Exception as e:
        click.echo(f"❌ Erro: {e}", err=True)
        raise click.Abort()


@auth.command()
def clear():
    """
    Limpa configurações de autenticação e cache
    
    Remove:
    - Preferência de método de auth
    - Cache de token do Device Flow
    
    Exemplo:
        fabricgov auth clear
    """
    click.echo("🗑️  Limpando autenticação...")
    
    try:
        # Remove preferência
        clear_auth_preference()
        click.echo("   ✓ Preferência de auth removida")
        
        # Remove cache do Device Flow
        from pathlib import Path
        cache_file = Path.home() / ".fabricgov_token_cache.json"
        if cache_file.exists():
            cache_file.unlink()
            click.echo("   ✓ Cache de token removido")
        
        click.echo()
        click.echo("✅ Autenticação limpa!")
        click.echo("   Execute 'fabricgov auth sp' ou 'fabricgov auth device' para autenticar novamente")
        
    except Exception as e:
        click.echo(f"❌ Erro ao limpar: {e}", err=True)
        raise click.Abort()