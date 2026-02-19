"""
Exceções customizadas para a biblioteca fabricgov.
"""


class FabricGovError(Exception):
    """Classe base para todas as exceções da lib."""
    pass


class AuthenticationError(FabricGovError):
    """Erro de autenticação (token inválido, credenciais incorretas)."""
    pass


class FabricAPIError(FabricGovError):
    """
    Erro retornado pela API do Fabric ou Power BI.
    
    Attributes:
        status_code: Código HTTP do erro
        endpoint: Endpoint que falhou
        message: Mensagem de erro
        response_body: Corpo completo da resposta (se disponível)
    """
    
    def __init__(
        self,
        message: str,
        status_code: int,
        endpoint: str,
        response_body: str | None = None,
    ):
        self.status_code = status_code
        self.endpoint = endpoint
        self.message = message
        self.response_body = response_body
        super().__init__(self._format_message())
    
    def _format_message(self) -> str:
        msg = f"[{self.status_code}] {self.message}\nEndpoint: {self.endpoint}"
        if self.response_body:
            msg += f"\nDetalhes: {self.response_body[:500]}"  # Limita a 500 chars
        return msg


class BadRequestError(FabricAPIError):
    """Erro 400 - requisição mal formada."""
    pass


class UnauthorizedError(FabricAPIError):
    """Erro 401 - token inválido ou expirado."""
    pass


class ForbiddenError(FabricAPIError):
    """Erro 403 - sem permissões necessárias."""
    pass


class NotFoundError(FabricAPIError):
    """Erro 404 - recurso não encontrado."""
    pass


class TooManyRequestsError(FabricAPIError):
    """Erro 429 - rate limit atingido."""
    pass


class InternalServerError(FabricAPIError):
    """Erro 500 - erro interno do servidor Microsoft."""
    pass


class ServiceUnavailableError(FabricAPIError):
    """Erro 503 - serviço temporariamente indisponível."""
    pass