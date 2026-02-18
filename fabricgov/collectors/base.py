from abc import ABC, abstractmethod
from typing import Any
import httpx
import time
from fabricgov.auth.base import AuthProvider


class BaseCollector(ABC):
    """
    Classe base para todos os coletores de dados do Fabric.
    
    Responsabilidades:
    - Gerenciar autenticação via AuthProvider
    - Fazer chamadas HTTP com retry e rate limiting
    - Abstrair paginação com continuationToken
    - Prover métodos helper para coletores concretos
    """

    def __init__(
        self,
        auth: AuthProvider,
        base_url: str,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        request_delay: float = 0.1,
    ) -> None:
        """
        Args:
            auth: Provedor de autenticação (ServicePrincipalAuth ou DeviceFlowAuth)
            base_url: URL base da API (definida pelo coletor concreto)
            timeout: Timeout em segundos para cada request
            max_retries: Número máximo de tentativas em caso de erro transiente
            retry_delay: Delay base entre retries (exponencial backoff)
            request_delay: Delay entre requests sucessivos (rate limiting básico)
        """
        self._auth = auth
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._request_delay = request_delay
        self._client = httpx.Client(timeout=timeout)

    def __del__(self):
        """Fecha o cliente HTTP ao destruir o coletor."""
        if hasattr(self, "_client"):
            self._client.close()

    @abstractmethod
    def collect(self) -> dict[str, Any]:
        """
        Método abstrato que cada coletor concreto deve implementar.
        Retorna um dicionário com os dados coletados.
        """
        pass

    # ── HTTP helpers ──────────────────────────────────────────────────────

    def _get(
        self,
        endpoint: str,
        scope: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Faz um GET request com retry automático e rate limiting.

        Args:
            endpoint: Path do endpoint (ex: "/v1/workspaces")
            scope: OAuth2 scope para obter o token
            params: Query parameters opcionais

        Returns:
            Resposta JSON como dict

        Raises:
            httpx.HTTPStatusError: se todas as tentativas falharem
        """
        url = f"{self._base_url}{endpoint}"
        token = self._auth.get_token(scope)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        for attempt in range(self._max_retries):
            try:
                time.sleep(self._request_delay)  # rate limiting básico
                response = self._client.get(url, headers=headers, params=params)
                response.raise_for_status()
                return response.json()

            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:  # Too Many Requests
                    # Exponential backoff
                    delay = self._retry_delay * (2 ** attempt)
                    time.sleep(delay)
                    continue
                elif e.response.status_code >= 500:  # Server errors
                    if attempt < self._max_retries - 1:
                        delay = self._retry_delay * (2 ** attempt)
                        time.sleep(delay)
                        continue
                raise  # Client errors (4xx) não fazem retry

            except (httpx.TimeoutException, httpx.ConnectError) as e:
                if attempt < self._max_retries - 1:
                    delay = self._retry_delay * (2 ** attempt)
                    time.sleep(delay)
                    continue
                raise

        # Se chegou aqui, todas as tentativas falharam
        raise httpx.HTTPStatusError(
            f"Falha após {self._max_retries} tentativas",
            request=response.request,
            response=response,
        )

    def _paginate(
        self,
        endpoint: str,
        scope: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Itera automaticamente por resultados paginados usando continuationToken.
        
        Padrão Fabric: a resposta tem {"value": [...], "continuationToken": "..."}
        Se não houver continuationToken, a paginação termina.

        Args:
            endpoint: Path do endpoint
            scope: OAuth2 scope
            params: Query parameters iniciais

        Returns:
            Lista agregada de todos os itens coletados
        """
        all_items = []
        params = params or {}
        continuation_token = None

        while True:
            if continuation_token:
                params["continuationToken"] = continuation_token

            response = self._get(endpoint, scope, params)
            
            # Acumula os itens
            items = response.get("value", [])
            all_items.extend(items)

            # Verifica se há mais páginas
            continuation_token = response.get("continuationToken")
            if not continuation_token:
                break

        return all_items