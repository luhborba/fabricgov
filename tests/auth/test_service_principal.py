import pytest
from unittest.mock import MagicMock, patch
from fabricgov.auth.service_principal import ServicePrincipalAuth
from fabricgov.auth.base import AuthProvider, AuthenticationError


@pytest.fixture(autouse=True)
def mock_msal_confidential(mocker):
    """
    Mocka ConfidentialClientApplication antes de qualquer instanciação.
    Aplicado automaticamente em todos os testes deste arquivo.
    """
    mock_app = MagicMock()
    mocker.patch(
        "fabricgov.auth.service_principal.msal.ConfidentialClientApplication",
        return_value=mock_app,
    )
    return mock_app


# ── from_params ───────────────────────────────────────────────────────────────

class TestFromParams:

    def test_instancia_com_credenciais_validas(self):
        auth = ServicePrincipalAuth.from_params(
            tenant_id="tenant-123",
            client_id="client-123",
            client_secret="secret-123",
        )
        assert isinstance(auth, ServicePrincipalAuth)

    def test_respeita_protocolo_auth_provider(self):
        auth = ServicePrincipalAuth.from_params(
            tenant_id="tenant-123",
            client_id="client-123",
            client_secret="secret-123",
        )
        assert isinstance(auth, AuthProvider)

    def test_erro_tenant_id_vazio(self):
        with pytest.raises(ValueError, match="tenant_id"):
            ServicePrincipalAuth.from_params(
                tenant_id="",
                client_id="client-123",
                client_secret="secret-123",
            )

    def test_erro_client_id_vazio(self):
        with pytest.raises(ValueError, match="client_id"):
            ServicePrincipalAuth.from_params(
                tenant_id="tenant-123",
                client_id="",
                client_secret="secret-123",
            )

    def test_erro_client_secret_vazio(self):
        with pytest.raises(ValueError, match="client_secret"):
            ServicePrincipalAuth.from_params(
                tenant_id="tenant-123",
                client_id="client-123",
                client_secret="",
            )

    def test_erro_multiplos_campos_vazios(self):
        with pytest.raises(ValueError) as exc:
            ServicePrincipalAuth.from_params(
                tenant_id="",
                client_id="",
                client_secret="",
            )
        assert "tenant_id" in str(exc.value)
        assert "client_id" in str(exc.value)
        assert "client_secret" in str(exc.value)

    def test_erro_apenas_espacos(self):
        with pytest.raises(ValueError, match="tenant_id"):
            ServicePrincipalAuth.from_params(
                tenant_id="   ",
                client_id="client-123",
                client_secret="secret-123",
            )


# ── from_env ──────────────────────────────────────────────────────────────────

class TestFromEnv:

    def test_instancia_com_env_vars(self, monkeypatch):
        monkeypatch.setenv("FABRICGOV_TENANT_ID", "tenant-env")
        monkeypatch.setenv("FABRICGOV_CLIENT_ID", "client-env")
        monkeypatch.setenv("FABRICGOV_CLIENT_SECRET", "secret-env")
        auth = ServicePrincipalAuth.from_env()
        assert isinstance(auth, ServicePrincipalAuth)

    def test_erro_env_vars_ausentes(self, monkeypatch, mocker):
        monkeypatch.delenv("FABRICGOV_TENANT_ID", raising=False)
        monkeypatch.delenv("FABRICGOV_CLIENT_ID", raising=False)
        monkeypatch.delenv("FABRICGOV_CLIENT_SECRET", raising=False)
        mocker.patch("fabricgov.auth.service_principal.load_dotenv")
        with pytest.raises(ValueError):
            ServicePrincipalAuth.from_env()

    def test_env_file_customizado(self, tmp_path, monkeypatch):
        monkeypatch.delenv("FABRICGOV_TENANT_ID", raising=False)
        monkeypatch.delenv("FABRICGOV_CLIENT_ID", raising=False)
        monkeypatch.delenv("FABRICGOV_CLIENT_SECRET", raising=False)
        env_file = tmp_path / ".env.test"
        env_file.write_text(
            "FABRICGOV_TENANT_ID=tenant-file\n"
            "FABRICGOV_CLIENT_ID=client-file\n"
            "FABRICGOV_CLIENT_SECRET=secret-file\n"
        )
        auth = ServicePrincipalAuth.from_env(env_file=str(env_file))
        assert isinstance(auth, ServicePrincipalAuth)


# ── get_token ─────────────────────────────────────────────────────────────────

class TestGetToken:

    def test_retorna_token_com_sucesso(self, mock_msal_confidential):
        mock_msal_confidential.acquire_token_for_client.return_value = {
            "access_token": "token-fake-123"
        }
        auth = ServicePrincipalAuth.from_params(
            tenant_id="tenant-123",
            client_id="client-123",
            client_secret="secret-123",
        )
        token = auth.get_token("https://api.fabric.microsoft.com/.default")
        assert token == "token-fake-123"

    def test_lanca_authentication_error_em_falha(self, mock_msal_confidential):
        mock_msal_confidential.acquire_token_for_client.return_value = {
            "error": "invalid_client",
            "error_description": "Client secret incorreto",
        }
        auth = ServicePrincipalAuth.from_params(
            tenant_id="tenant-123",
            client_id="client-123",
            client_secret="secret-errado",
        )
        with pytest.raises(AuthenticationError, match="invalid_client"):
            auth.get_token("https://api.fabric.microsoft.com/.default")

    def test_mensagem_de_erro_contem_descricao(self, mock_msal_confidential):
        mock_msal_confidential.acquire_token_for_client.return_value = {
            "error": "invalid_client",
            "error_description": "Client secret incorreto",
        }
        auth = ServicePrincipalAuth.from_params(
            tenant_id="tenant-123",
            client_id="client-123",
            client_secret="secret-errado",
        )
        with pytest.raises(AuthenticationError, match="Client secret incorreto"):
            auth.get_token("https://api.fabric.microsoft.com/.default")