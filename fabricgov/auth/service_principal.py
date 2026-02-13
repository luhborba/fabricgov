import os
import msal
from dotenv import load_dotenv
from fabricgov.auth.base import AuthProvider, AuthenticationError


class ServicePrincipalAuth:
    """
    Autenticação via Service Principal (client credentials flow).
    Uso recomendado: automação, CI/CD, notebooks agendados.
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            validate_authority=False,
        )

    @classmethod
    def from_params(
        cls,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ) -> "ServicePrincipalAuth":
        cls._validate_params(tenant_id, client_id, client_secret)
        return cls(tenant_id, client_id, client_secret)

    @classmethod
    def from_env(cls, env_file: str | None = None) -> "ServicePrincipalAuth":
        load_dotenv(dotenv_path=env_file, override=False)
        tenant_id     = os.getenv("FABRICGOV_TENANT_ID", "")
        client_id     = os.getenv("FABRICGOV_CLIENT_ID", "")
        client_secret = os.getenv("FABRICGOV_CLIENT_SECRET", "")
        cls._validate_params(tenant_id, client_id, client_secret)
        return cls(tenant_id, client_id, client_secret)

    def get_token(self, scope: str) -> str:
        result = self._app.acquire_token_for_client(scopes=[scope])
        if "access_token" in result:
            return result["access_token"]
        error       = result.get("error", "unknown_error")
        description = result.get("error_description", "sem detalhes")
        raise AuthenticationError(
            f"Falha na autenticação via Service Principal.\n"
            f"Erro: {error}\n"
            f"Detalhe: {description}"
        )

    @staticmethod
    def _validate_params(tenant_id: str, client_id: str, client_secret: str) -> None:
        campos = {
            "tenant_id / FABRICGOV_TENANT_ID": tenant_id,
            "client_id / FABRICGOV_CLIENT_ID": client_id,
            "client_secret / FABRICGOV_CLIENT_SECRET": client_secret,
        }
        # Corrigido: trata None e string vazia
        faltando = [
            nome for nome, valor in campos.items()
            if not valor or not valor.strip()
        ]
        if faltando:
            raise ValueError(
                f"Credenciais ausentes ou vazias: {', '.join(faltando)}\n"
                f"Forneça via from_params() ou defina as variáveis de ambiente."
            )