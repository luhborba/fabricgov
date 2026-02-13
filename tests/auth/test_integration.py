import pytest
from fabricgov.auth.service_principal import ServicePrincipalAuth
from fabricgov.auth.base import AuthenticationError

# Marca todos os testes deste arquivo como integração
# Só rodam com: pytest -m integration
pytestmark = pytest.mark.integration

FABRIC_SCOPE = "https://api.fabric.microsoft.com/.default"
POWERBI_SCOPE = "https://analysis.windows.net/powerbi/api/.default"


class TestServicePrincipalIntegration:

    def test_obtem_token_fabric_via_env(self):
        """Requer FABRICGOV_TENANT_ID, FABRICGOV_CLIENT_ID, FABRICGOV_CLIENT_SECRET no .env"""
        auth = ServicePrincipalAuth.from_env()
        token = auth.get_token(FABRIC_SCOPE)

        assert token is not None
        assert len(token) > 100  # tokens JWT são longos
        assert isinstance(token, str)

    def test_obtem_token_powerbi_via_env(self):
        """Requer FABRICGOV_TENANT_ID, FABRICGOV_CLIENT_ID, FABRICGOV_CLIENT_SECRET no .env"""
        auth = ServicePrincipalAuth.from_env()
        token = auth.get_token(POWERBI_SCOPE)

        assert token is not None
        assert isinstance(token, str)

    def test_cache_retorna_mesmo_token(self):
        """Duas chamadas com o mesmo scope devem retornar o mesmo token (cache MSAL)"""
        auth = ServicePrincipalAuth.from_env()
        token1 = auth.get_token(FABRIC_SCOPE)
        token2 = auth.get_token(FABRIC_SCOPE)

        assert token1 == token2

    def test_credenciais_invalidas_lancam_authentication_error(self):
        auth = ServicePrincipalAuth.from_params(
            tenant_id="tenant-invalido",
            client_id="client-invalido",
            client_secret="secret-invalido",
        )
        with pytest.raises(AuthenticationError):
            auth.get_token(FABRIC_SCOPE)