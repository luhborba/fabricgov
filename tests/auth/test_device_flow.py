import pytest
from unittest.mock import MagicMock
from fabricgov.auth.device_flow import DeviceFlowAuth
from fabricgov.auth.base import AuthProvider, AuthenticationError


@pytest.fixture(autouse=True)
def mock_msal_public(mocker):
    """
    Mocka PublicClientApplication antes de qualquer instanciação.
    Aplicado automaticamente em todos os testes deste arquivo.
    """
    mock_app = MagicMock()
    mocker.patch(
        "fabricgov.auth.device_flow.msal.PublicClientApplication",
        return_value=mock_app,
    )
    return mock_app


# ── instanciação ──────────────────────────────────────────────────────────────

class TestInstanciacao:

    def test_instancia_com_parametros_validos(self):
        auth = DeviceFlowAuth(tenant_id="tenant-123", client_id="client-123")
        assert isinstance(auth, DeviceFlowAuth)

    def test_respeita_protocolo_auth_provider(self):
        auth = DeviceFlowAuth(tenant_id="tenant-123", client_id="client-123")
        assert isinstance(auth, AuthProvider)


# ── get_token ─────────────────────────────────────────────────────────────────

class TestGetToken:

    def test_retorna_token_do_cache(self, mock_msal_public):
        mock_msal_public.get_accounts.return_value = [{"username": "user@tenant.com"}]
        mock_msal_public.acquire_token_silent.return_value = {
            "access_token": "token-cache-123"
        }
        auth = DeviceFlowAuth(tenant_id="tenant-123", client_id="client-123")
        token = auth.get_token("https://api.fabric.microsoft.com/.default")
        assert token == "token-cache-123"

    def test_inicia_device_flow_sem_cache(self, mock_msal_public):
        mock_msal_public.get_accounts.return_value = []
        mock_msal_public.initiate_device_flow.return_value = {
            "user_code": "ABC123",
            "verification_uri": "https://microsoft.com/devicelogin",
            "device_code": "device-code-fake",
            "expires_in": 900,
        }
        mock_msal_public.acquire_token_by_device_flow.return_value = {
            "access_token": "token-device-123"
        }
        auth = DeviceFlowAuth(tenant_id="tenant-123", client_id="client-123")
        token = auth.get_token("https://api.fabric.microsoft.com/.default")
        assert token == "token-device-123"

    def test_lanca_erro_se_device_flow_falhar(self, mock_msal_public):
        mock_msal_public.get_accounts.return_value = []
        mock_msal_public.initiate_device_flow.return_value = {
            "error": "invalid_client",
            "error_description": "Client ID inválido",
        }
        auth = DeviceFlowAuth(tenant_id="tenant-123", client_id="client-invalido")
        with pytest.raises(AuthenticationError, match="invalid_client"):
            auth.get_token("https://api.fabric.microsoft.com/.default")

    def test_lanca_erro_se_autenticacao_expirar(self, mock_msal_public):
        mock_msal_public.get_accounts.return_value = []
        mock_msal_public.initiate_device_flow.return_value = {
            "user_code": "ABC123",
            "verification_uri": "https://microsoft.com/devicelogin",
            "device_code": "device-code-fake",
            "expires_in": 900,
        }
        mock_msal_public.acquire_token_by_device_flow.return_value = {
            "error": "authorization_pending",
            "error_description": "Flow expirou sem autenticação",
        }
        auth = DeviceFlowAuth(tenant_id="tenant-123", client_id="client-123")
        with pytest.raises(AuthenticationError, match="authorization_pending"):
            auth.get_token("https://api.fabric.microsoft.com/.default")