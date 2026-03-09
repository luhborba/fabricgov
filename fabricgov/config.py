from pathlib import Path
import json
from typing import Literal

AuthMethod = Literal["service_principal", "device_flow", "keyvault"]

# Arquivo de configuração de auth
AUTH_CONFIG_FILE = Path("output/.auth_config.json")


def save_auth_preference(method: AuthMethod) -> None:
    """
    Salva o método de autenticação utilizado por último.

    Args:
        method: "service_principal", "device_flow" ou "keyvault"
    """
    AUTH_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    config = {"last_auth_method": method}
    with open(AUTH_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def save_keyvault_config(vault_url: str, secret_names: dict[str, str]) -> None:
    """
    Salva a configuração do Key Vault no arquivo de auth.
    Armazena apenas referências (nomes dos secrets), nunca credenciais.

    Args:
        vault_url: URL completa do Key Vault (ex: https://meu-vault.vault.azure.net/)
        secret_names: mapeamento {"tenant_id": "nome-secret", "client_id": ..., "client_secret": ...}
    """
    AUTH_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    config = {
        "last_auth_method": "keyvault",
        "vault_url": vault_url,
        "secret_names": secret_names,
    }
    with open(AUTH_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def get_auth_preference() -> AuthMethod | None:
    """
    Retorna o método de autenticação usado por último.

    Returns:
        "service_principal", "device_flow", "keyvault", ou None se nunca autenticou
    """
    if not AUTH_CONFIG_FILE.exists():
        return None
    try:
        with open(AUTH_CONFIG_FILE, "r") as f:
            config = json.load(f)
        return config.get("last_auth_method")
    except Exception:
        return None


def get_keyvault_config() -> dict | None:
    """
    Retorna a configuração do Key Vault salva (vault_url + secret_names).

    Returns:
        dict com vault_url e secret_names, ou None se o método não for keyvault
    """
    if not AUTH_CONFIG_FILE.exists():
        return None
    try:
        with open(AUTH_CONFIG_FILE, "r") as f:
            config = json.load(f)
        if config.get("last_auth_method") == "keyvault":
            return {
                "vault_url": config.get("vault_url", ""),
                "secret_names": config.get("secret_names", {}),
            }
        return None
    except Exception:
        return None


def clear_auth_preference() -> None:
    """Remove o arquivo de configuração de auth."""
    if AUTH_CONFIG_FILE.exists():
        AUTH_CONFIG_FILE.unlink()


def require_auth() -> None:
    """
    Valida se o usuário já autenticou.
    
    Raises:
        RuntimeError: Se nenhuma autenticação foi configurada
    """
    if get_auth_preference() is None:
        raise RuntimeError(
            "❌ Nenhuma autenticação configurada!\n"
            "   Execute primeiro:\n"
            "     fabricgov auth test    (Service Principal)\n"
            "     fabricgov auth device  (Device Flow)"
        )