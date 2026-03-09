# Azure Key Vault — Quick Start

Store Service Principal credentials in Azure Key Vault instead of plain-text files on disk.

> Full authentication guide: [authentication.md](authentication.md)

---

## Prerequisites

- Key Vault created in Azure
- Role **Key Vault Secrets User** assigned to your user or SP on the vault
- `pip install fabricgov[keyvault]`

---

## 1. Create the secrets in the vault

```bash
az keyvault secret set --vault-name MY-VAULT --name fabricgov-tenant-id     --value "<tenant-id>"
az keyvault secret set --vault-name MY-VAULT --name fabricgov-client-id     --value "<client-id>"
az keyvault secret set --vault-name MY-VAULT --name fabricgov-client-secret --value "<client-secret>"
```

The `fabricgov-*` names are the tool's defaults. You can use any names — see [Custom names](#custom-names).

---

## 2. Authenticate fabricgov

```bash
fabricgov auth keyvault --vault-url https://MY-VAULT.vault.azure.net/
```

fabricgov will:
1. Connect to the vault via `DefaultAzureCredential` (uses `az login` locally)
2. Fetch the 3 secrets
3. Validate the token against Microsoft Fabric
4. Save only the vault URL and secret names to `output/.auth_config.json`

---

## 3. Collect as usual

```bash
fabricgov collect all
```

On every run, fabricgov fetches credentials directly from the vault — no secrets ever touch disk.

---

## Custom names

If your vault already has secrets under different names:

```bash
fabricgov auth keyvault \
  --vault-url            https://MY-VAULT.vault.azure.net/ \
  --tenant-id-secret     corp-fabric-tenant \
  --client-id-secret     corp-fabric-client \
  --client-secret-secret corp-fabric-secret
```

---

## Vault authentication by environment

| Environment | How to authenticate to the vault |
|---|---|
| **Local** | Run `az login` before using fabricgov |
| **Azure VM / ACI** | Managed Identity (no extra configuration) |
| **CI/CD** | Env vars `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` of a SP with vault access |

---

## Common errors

**`Dependencies not found`**
```bash
pip install fabricgov[keyvault]
```

**`CredentialUnavailableError` / no vault access**
- Run `az login` (local development)
- Or check that Managed Identity is enabled on your VM/container

**`ResourceNotFoundError: secret not found`**
- Confirm secret names in the Azure portal
- Use `--tenant-id-secret`, `--client-id-secret`, `--client-secret-secret` if names differ from defaults

**`ForbiddenError` on the vault**
- Verify your user/SP has the **Key Vault Secrets User** role on the vault

---

**[← Authentication](authentication.md)** | **[Back to README](../../README.en.md)**
