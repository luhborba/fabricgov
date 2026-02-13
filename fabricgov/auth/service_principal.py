import msal
import os
from dotenv import load_dotenv
from fabricgov.auth.base import AuthProvider, AuthenticationError

class ServicePrincipalAuth:
    """
    Autenticação usando Service Principal.
    """

    def ___init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._app = msal.ConfidentialClientApplication(
            client_id = self.client_id,
            client_credential = self.client_secret,
            authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        )

    @classmethod
    def from_params(
        cls,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ) -> "ServicePrincipalAuth":
        """
        Cria uma instância de ServicePrincipalAuth a partir dos parâmetros fornecidos.

        Args:
            tenant_id (str): O ID do locatário do Azure AD.
            client_id (str): O ID do aplicativo registrado no Azure AD.
            client_secret (str): O segredo do cliente para o aplicativo registrado.

        Returns:
            ServicePrincipalAuth: Uma instância de ServicePrincipalAuth configurada com os parâmetros fornecidos.
        """
        cls._validate_params(tenant_id, client_id, client_secret)
        return cls(tenant_id, client_id, client_secret)
    
    @classmethod
    def from_env(cls, env_file: str | None = None) -> "ServicePrincipalAuth":
        """
        Cria uma instância de ServicePrincipalAuth a partir de variáveis de ambiente.

        Args:
            env_file (str | None): O caminho para o arquivo .env que contém as variáveis de ambiente. 
                                    Se None, as variáveis de ambiente do sistema serão usadas.

        Returns:
            ServicePrincipalAuth: Uma instância de ServicePrincipalAuth configurada com as variáveis de ambiente.
        """
        if env_file:
            load_dotenv(env_file)

        tenant_id = os.getenv("FABRICGOV_TENANT_ID")
        client_id = os.getenv("FABRICGOV_CLIENT_ID")
        client_secret = os.getenv("FABRICGOV_CLIENT_SECRET")

        cls._validate_params(tenant_id, client_id, client_secret)
        return cls(tenant_id, client_id, client_secret)
    
    def get_token(self, scope: str) -> str:
        """
        Obtém um token de autenticação para o escopo especificado.

        Args:
            scope (str): O escopo para o qual o token deve ser obtido.

        Returns:
            str: O token de autenticação.

        Raises:
            AuthenticationError: Se ocorrer um erro durante a obtenção do token.
        """
        result = self._app.acquire_token_for_client(scopes=[scope])
        if "access_token" in result:
            return result["access_token"]
        else:
            error       = result.get("error", "unknown_error")
            description = result.get("error_description", "sem detalhes")
            raise AuthenticationError(
                f"Falha na autenticação via Service Principal.\n"
                f"Erro: {error}\n"
                f"Detalhe: {description}"
            )
        
    @staticmethod
    def _validate_params(tenant_id: str, client_id: str, client_secret: str):
        """
        Valida os parâmetros necessários para a autenticação via Service Principal.
        
        Args:
            tenant_id (str): O ID do locatário do Azure AD.
            client_id (str): O ID do aplicativo registrado no Azure AD.
            client_secret (str): O segredo do cliente para o aplicativo registrado.
        """
        campos = {
                    "tenant_id / FABRICGOV_TENANT_ID": tenant_id,
                    "client_id / FABRICGOV_CLIENT_ID": client_id,
                    "client_secret / FABRICGOV_CLIENT_SECRET": client_secret,
                }
        faltando = [nome for nome, valor in campos.items() if not valor.strip()]
        if faltando:
            raise ValueError(
                f"Credenciais ausentes ou vazias: {', '.join(faltando)}\n"
                f"Forneça via from_params() ou defina as variáveis de ambiente."
            )
        