from typing import Protocol, runtime_checkable
from fabricgov.exceptions import AuthenticationError

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
    
@runtime_checkable
class AuthProvider(Protocol):
    """
    Contrato que todo provedor de autenticação deve respeitar.
    """

    def get_token(self, scope: str) -> str:
        """
        Retorna um Bearer token válido para o scope informado.

        Args:
            scope: URL do scope OAuth2.
                   Ex: "https://api.fabric.microsoft.com/.default"

        Returns:
            Token de acesso como string.

        Raises:
            AuthenticationError: se não for possível obter o token.
        """
        ...