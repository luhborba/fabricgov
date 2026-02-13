import msal
from fabricgov.auth.base import AuthProvider, AuthenticationError

class DeviceFlowAuth:
    """
    Autenticação interativa via Device Flow.
    """

    def __init__(self, tenant_id: str, client_id: str) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._app = msal.PublicClientApplication(
            client_id=client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            validate_authority=False,
        )
    
    def get_token(self, scope: str) -> str:
        """
        Inicia o Device Flow para obter um token de autenticação para o escopo especificado.
        """
    
        accounts = self._app.get_accounts()
        if accounts:
            result = self._app.acquire_token_silent(
                scopes=[scope],
                account=accounts[0]
            )
            if result and "access_token" in result:
                return result["access_token"]
        
        flow = self._app.initiate_device_flow(scopes=[scope])

        if "user_code" not in flow:
            raise AuthenticationError(
                f"Falha ao iniciar Device Flow. \n"
                f"Error: {flow.get('error',"unknown_error")}\n"
                f"Detalhe: {flow.get('error_description', 'sem detalhes')}"
            )
        
        print("\n" + "─" * 50)
        print("  Autenticação necessária")
        print("─" * 50)
        print(f"  1. Acesse: {flow['verification_uri']}")
        print(f"  2. Digite o código: {flow['user_code']}")
        print(f"  3. Aguardando autenticação...")
        print("─" * 50 + "\n")

        result = self._app.acquire_token_by_device_flow(flow)

        if "access_token" in result:
            return result["access_token"]

        error       = result.get("error", "unknown_error")
        description = result.get("error_description", "sem detalhes")
        raise AuthenticationError(
            f"Falha na autenticação via Device Flow.\n"
            f"Erro: {error}\n"
            f"Detalhe: {description}"
        )
    