import msal
import json
from pathlib import Path
from datetime import datetime, timedelta
from fabricgov.auth.base import AuthProvider
from fabricgov.exceptions import AuthenticationError


class DeviceFlowAuth:
    """
    Autenticação interativa via Device Flow.
    
    Uso recomendado: CLI por humanos, ambientes sem browser.
    Suporta MFA — o flow completo acontece no browser do usuário.
    
    Exemplos:
        # Opção 1: Multi-tenant (descobre tenant automaticamente)
        auth = DeviceFlowAuth()
        
        # Opção 2: Tenant específico
        auth = DeviceFlowAuth(tenant_id="seu-tenant-id")
        
        # Opção 3: Client ID customizado
        auth = DeviceFlowAuth(client_id="seu-client-id")
    """

    # Client ID público do Azure CLI (usado como padrão)
    DEFAULT_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

    def __init__(
        self,
        tenant_id: str | None = None,
        client_id: str | None = None,
    ) -> None:
        """
        Args:
            tenant_id: ID do tenant. Se None, usa '/common' (multi-tenant).
            client_id: ID do App Registration. Se None, usa client_id público do Azure CLI.
        """
        self._tenant_id = tenant_id or "common"
        self._client_id = client_id or self.DEFAULT_CLIENT_ID
        
        try:
            self._app = msal.PublicClientApplication(
                client_id=self._client_id,
                authority=f"https://login.microsoftonline.com/{self._tenant_id}",
                validate_authority=False,
            )
        except ValueError as e:
            raise AuthenticationError(
                f"Falha ao inicializar autenticação.\n"
                f"Tenant ID: {self._tenant_id}\n"
                f"Client ID: {self._client_id}\n"
                f"Detalhe: {str(e)}"
            )

    def _get_cache_file(self) -> Path:
        """Retorna o caminho do arquivo de cache."""
        return Path.home() / ".fabricgov_token_cache.json"
    
    def _load_cache(self) -> dict | None:
        """
        Carrega token do cache se ainda for válido.
        
        Returns:
            dict com access_token e expires_at, ou None se inválido/inexistente
        """
        cache_file = self._get_cache_file()
        
        if not cache_file.exists():
            return None
        
        try:
            with open(cache_file, "r") as f:
                cache = json.load(f)
            
            # Verifica se token ainda é válido
            expires_at = datetime.fromisoformat(cache.get("expires_at", ""))
            if datetime.now() < expires_at:
                return cache
            
        except Exception:
            pass
        
        return None
    
    def _save_cache(self, access_token: str, expires_in: int) -> None:
        """
        Salva token no cache.
        
        Args:
            access_token: Token JWT
            expires_in: Tempo de vida em segundos
        """
        cache_file = self._get_cache_file()
        
        expires_at = datetime.now() + timedelta(seconds=expires_in - 300)  # 5min de margem
        
        cache = {
            "access_token": access_token,
            "expires_at": expires_at.isoformat()
        }
        
        with open(cache_file, "w") as f:
            json.dump(cache, f, indent=2)

    def get_token(self, scope: str) -> str:
        """
        Inicia Device Flow e aguarda autenticação do usuário.
        
        Na primeira execução:
        - Imprime URL e código no terminal
        - Aguarda usuário autenticar no browser
        
        Execuções seguintes:
        - Usa token em cache (se ainda válido)
        
        Args:
            scope: Ex: "https://api.fabric.microsoft.com/.default"

        Returns:
            Bearer token como string.

        Raises:
            AuthenticationError: se o flow expirar ou for cancelado.
        """
        # Tenta usar cache local primeiro (arquivo .fabricgov_token_cache.json)
        cached = self._load_cache()
        if cached:
            return cached["access_token"]
        
        # Tenta reusar token em cache do MSAL
        accounts = self._app.get_accounts()
        if accounts:
            result = self._app.acquire_token_silent(
                scopes=[scope],
                account=accounts[0]
            )
            if result and "access_token" in result:
                self._save_cache(result["access_token"], result.get("expires_in", 3600))
                return result["access_token"]

        # Inicia novo Device Flow
        flow = self._app.initiate_device_flow(scopes=[scope])

        if "user_code" not in flow:
            raise AuthenticationError(
                f"Falha ao iniciar Device Flow.\n"
                f"Erro: {flow.get('error', 'unknown_error')}\n"
                f"Detalhe: {flow.get('error_description', 'sem detalhes')}"
            )

        # Instrução para o usuário
        print("\n" + "─" * 70)
        print("  AUTENTICAÇÃO NECESSÁRIA")
        print("─" * 70)
        print(f"  1. Acesse: {flow['verification_uri']}")
        print(f"  2. Digite o código: {flow['user_code']}")
        print(f"  3. Autentique com sua conta Microsoft")
        print("─" * 70)
        print("  Aguardando autenticação...")
        print("─" * 70 + "\n")

        result = self._app.acquire_token_by_device_flow(flow)

        if "access_token" in result:
            self._save_cache(result["access_token"], result.get("expires_in", 3600))
            return result["access_token"]

        error       = result.get("error", "unknown_error")
        description = result.get("error_description", "sem detalhes")
        raise AuthenticationError(
            f"Falha na autenticação via Device Flow.\n"
            f"Erro: {error}\n"
            f"Detalhe: {description}"
        )