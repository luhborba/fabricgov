import click
from fabricgov.auth import ServicePrincipalAuth, DeviceFlowAuth, KeyVaultAuth
from fabricgov.exceptions import AuthenticationError
from fabricgov.config import save_auth_preference, save_keyvault_config, clear_auth_preference


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
@click.option(
    "--vault-url", required=True,
    help="URL do Azure Key Vault (ex: https://meu-vault.vault.azure.net/)",
)
@click.option(
    "--tenant-id-secret", default="fabricgov-tenant-id", show_default=True,
    help="Nome do secret que contém o Tenant ID",
)
@click.option(
    "--client-id-secret", default="fabricgov-client-id", show_default=True,
    help="Nome do secret que contém o Client ID",
)
@click.option(
    "--client-secret-secret", default="fabricgov-client-secret", show_default=True,
    help="Nome do secret que contém o Client Secret",
)
def keyvault(vault_url, tenant_id_secret, client_id_secret, client_secret_secret):
    """
    Autenticação via Azure Key Vault (sem armazenar credenciais em texto plano)

    Busca as credenciais do Service Principal diretamente no Key Vault.
    A autenticação no vault usa DefaultAzureCredential, que aceita:
      - az login (desenvolvimento local)
      - Managed Identity (Azure VM / ACI / Functions)
      - Variáveis de ambiente AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET

    Exemplos:
        fabricgov auth keyvault --vault-url https://meu-vault.vault.azure.net/

        fabricgov auth keyvault \\
            --vault-url https://meu-vault.vault.azure.net/ \\
            --tenant-id-secret meu-tenant \\
            --client-id-secret meu-client \\
            --client-secret-secret meu-secret
    """
    click.echo("🔐 Conectando ao Azure Key Vault...")
    click.echo(f"   Vault: {vault_url}")

    secret_names = {
        "tenant_id": tenant_id_secret,
        "client_id": client_id_secret,
        "client_secret": client_secret_secret,
    }

    try:
        kv = KeyVaultAuth(vault_url=vault_url, secret_names=secret_names)

        click.echo("   Buscando credenciais...")
        sp = kv.to_service_principal()

        click.echo("   Validando token no Microsoft Fabric...")
        token = sp.get_token("https://analysis.windows.net/powerbi/api/.default")

        click.echo("✅ Autenticação via Key Vault bem-sucedida!")
        click.echo(f"   Token obtido: {token[:50]}...")

        save_keyvault_config(vault_url=vault_url, secret_names=secret_names)
        click.echo("   Configuração salva: Key Vault")

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