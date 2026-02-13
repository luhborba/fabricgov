from typing import Protocol, runtime_checkable

@runtime_checkable
class AuthProvider(Protocol):
    """
    Protocolo de autenticação para o FabricGov. 
    Qualquer classe que implemente este protocolo pode ser usada como um provedor de autenticação no sistema.
    """

    def get_token(self, scope: str) -> str:
        """
        Obtém um token de autenticação para o escopo especificado.

        Args:
            scope (str): O escopo para o qual o token deve ser obtido.

        Returns:
            str: O token de autenticação.

        Raises:
            AuthenticationError: Se ocorrer um erro durante a obtenção do token.
        """
        ...
    
class AuthenticationError(Exception):
    """Exceção personalizada para erros de autenticação."""
    pass