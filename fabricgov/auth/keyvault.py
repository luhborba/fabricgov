"""
KeyVaultAuth: busca credenciais do Service Principal no Azure Key Vault.

Requer dependências opcionais:
    pip install fabricgov[keyvault]
    # ou
    pip install azure-keyvault-secrets azure-identity

Autenticação no próprio Key Vault via DefaultAzureCredential, que tenta:
  1. Variáveis de ambiente (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET)
  2. Managed Identity (quando rodando em Azure VM / ACI / Functions)
  3. Azure CLI  (az login)
  4. Azure PowerShell
"""
from __future__ import annotations

from fabricgov.exceptions import AuthenticationError

try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient

    _KEYVAULT_AVAILABLE = True
except ImportError:
    _KEYVAULT_AVAILABLE = False


class KeyVaultAuth:
    """
    Busca as credenciais do Service Principal diretamente no Azure Key Vault,
    eliminando a necessidade de armazenar client_secret em texto plano.

    Uso típico (local com az login):
        kv = KeyVaultAuth("https://meu-vault.vault.azure.net/")
        sp = kv.to_service_principal()

    Uso em CI/CD (env vars AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET):
        kv = KeyVaultAuth("https://meu-vault.vault.azure.net/")
        sp = kv.to_service_principal()
    """

    DEFAULT_SECRET_NAMES: dict[str, str] = {
        "tenant_id": "fabricgov-tenant-id",
        "client_id": "fabricgov-client-id",
        "client_secret": "fabricgov-client-secret",
    }

    def __init__(self, vault_url: str, secret_names: dict[str, str] | None = None) -> None:
        if not _KEYVAULT_AVAILABLE:
            raise AuthenticationError(
                "Dependências do Key Vault não encontradas.\n"
                "Instale com: pip install fabricgov[keyvault]\n"
                "          ou: pip install azure-keyvault-secrets azure-identity"
            )
        self.vault_url = vault_url.rstrip("/")
        self.secret_names: dict[str, str] = {
            **self.DEFAULT_SECRET_NAMES,
            **(secret_names or {}),
        }

    def fetch_credentials(self) -> tuple[str, str, str]:
        """
        Conecta ao Key Vault e retorna (tenant_id, client_id, client_secret).

        Raises:
            AuthenticationError: se não conseguir autenticar no vault ou buscar os secrets.
        """
        try:
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=self.vault_url, credential=credential)

            tenant_id = client.get_secret(self.secret_names["tenant_id"]).value or ""
            client_id = client.get_secret(self.secret_names["client_id"]).value or ""
            client_secret = client.get_secret(self.secret_names["client_secret"]).value or ""

            return tenant_id, client_id, client_secret

        except AuthenticationError:
            raise
        except Exception as e:
            raise AuthenticationError(
                f"Erro ao buscar credenciais do Key Vault: {self.vault_url}\n"
                f"Detalhe: {e}\n\n"
                "Verifique:\n"
                "  • Autenticado no Azure CLI? Execute: az login\n"
                "  • URL do vault está correta?\n"
                f"  • Role 'Key Vault Secrets User' atribuída ao seu usuário/SP no vault?\n"
                f"  • Nomes dos secrets: {list(self.secret_names.values())}"
            ) from e

    def to_service_principal(self):
        """
        Busca as credenciais do vault e retorna um ServicePrincipalAuth pronto para uso.

        Returns:
            ServicePrincipalAuth autenticado com as credenciais do vault.
        """
        from fabricgov.auth.service_principal import ServicePrincipalAuth

        tenant_id, client_id, client_secret = self.fetch_credentials()
        return ServicePrincipalAuth.from_params(tenant_id, client_id, client_secret)
