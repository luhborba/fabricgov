# Authentication Guide

**fabricgov** supports three authentication modes to access Microsoft Fabric and Power BI APIs:

1. **Service Principal** — non-interactive authentication (recommended for automation)
2. **Device Flow** — interactive browser-based authentication (recommended for manual use)
3. **Azure Key Vault** — Service Principal without credentials on disk (recommended for production)

---

## 🔐 Service Principal (Automation)

### When to use
- Automated scripts
- CI/CD pipelines
- Scheduled notebooks
- Environments without human interaction

### Prerequisites

#### 1. Create an App Registration in Azure AD

1. Go to the [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** → **App registrations**
3. Click **New registration**
4. Configure:
   - **Name:** `fabricgov-automation` (or any name)
   - **Supported account types:** "Accounts in this organizational directory only"
   - **Redirect URI:** leave blank
5. Click **Register**

#### 2. Copy Credentials

After creating the App Registration:

- **Application (client) ID** → copy to `FABRICGOV_CLIENT_ID`
- **Directory (tenant) ID** → copy to `FABRICGOV_TENANT_ID`

#### 3. Create a Client Secret

1. In the side menu, go to **Certificates & secrets**
2. Click **New client secret**
3. Configure:
   - **Description:** `fabricgov-secret`
   - **Expires:** 24 months (or per your company policy)
4. Click **Add**
5. **IMPORTANT:** Copy the **Value** immediately (only shown once) → `FABRICGOV_CLIENT_SECRET`

#### 4. Configure API Permissions

1. In the side menu, go to **API permissions**
2. Click **Add a permission**
3. Select **Power BI Service**
4. Choose **Application permissions** (not "Delegated")
5. Add the following permissions:
   - `Tenant.Read.All`
   - `Workspace.ReadWrite.All`
6. Click **Add permissions**
7. **CRITICAL:** Click **Grant admin consent for [your tenant]**
   - Only a tenant admin can do this
   - Without this, the SP will not work

#### 5. Enable Service Principals in Fabric Admin Portal

1. Go to the [Power BI Portal](https://app.powerbi.com)
2. Navigate to **Settings** (gear icon) → **Admin portal**
3. In the side menu, select **Tenant settings**
4. Scroll to **Admin API settings**
5. Enable:
   - **Service principals can use Fabric APIs**
   - **Service principals can access read-only admin APIs**
6. Add the Service Principal to the allowed group (or select "Apply to the entire organization")
7. Click **Apply**

---

### Configuration

#### Option 1: Via `.env` file (recommended)

Create a `.env` file in the project root:
```env
FABRICGOV_TENANT_ID=00000000-0000-0000-0000-000000000000
FABRICGOV_CLIENT_ID=11111111-1111-1111-1111-111111111111
FABRICGOV_CLIENT_SECRET=your-client-secret-here
```

**Usage in code:**
```python
from fabricgov.auth import ServicePrincipalAuth

# Automatically reads from .env
auth = ServicePrincipalAuth.from_env()
```

#### Option 2: Via direct parameters
```python
from fabricgov.auth import ServicePrincipalAuth

auth = ServicePrincipalAuth.from_params(
    tenant_id="00000000-0000-0000-0000-000000000000",
    client_id="11111111-1111-1111-1111-111111111111",
    client_secret="your-client-secret-here"
)
```

#### Option 3: Via system environment variables
```bash
export FABRICGOV_TENANT_ID="00000000-0000-0000-0000-000000000000"
export FABRICGOV_CLIENT_ID="11111111-1111-1111-1111-111111111111"
export FABRICGOV_CLIENT_SECRET="your-client-secret-here"
```

---

### Full Example
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exceptions import ForbiddenError, UnauthorizedError

try:
    auth = ServicePrincipalAuth.from_env()
    collector = WorkspaceInventoryCollector(auth=auth)
    result = collector.collect()
    print(f"✓ Collected {result['summary']['total_workspaces']} workspaces")

except UnauthorizedError as e:
    print(f"❌ Invalid credentials: {e.message}")

except ForbiddenError as e:
    print(f"❌ Access denied: {e.message}")
    print("   → Check if the SP is in the Fabric Administrators group")
```

---

## 🌐 Device Flow (Interactive)

### When to use
- Manual use via terminal
- Local development
- Environments where creating a Service Principal is not possible
- When the user needs to authenticate with their own credentials

### Advantages
- ✅ No `tenant_id` or `client_id` required (uses public defaults)
- ✅ No need to create an App Registration in Azure AD
- ✅ MFA supported automatically
- ✅ Token cache between executions (valid for ~1h)

### Requirements
- The authenticating user must have **Fabric Administrator** permissions in the tenant
- Access to a browser for authentication

---

### Usage
```python
from fabricgov.auth import DeviceFlowAuth

auth = DeviceFlowAuth()

# On first run, displays:
# ──────────────────────────────────────────────────────────────────
#   AUTHENTICATION REQUIRED
# ──────────────────────────────────────────────────────────────────
#   1. Go to: https://microsoft.com/devicelogin
#   2. Enter the code: ABC12DEF
#   3. Sign in with your Microsoft account
# ──────────────────────────────────────────────────────────────────
#   Waiting for authentication...
# ──────────────────────────────────────────────────────────────────

# After authenticating in the browser, the script continues automatically
```

---

### Advanced Usage (Specific Tenant)
```python
# Force authentication against a specific tenant
auth = DeviceFlowAuth(tenant_id="your-tenant-id")

# With your own App Registration
auth = DeviceFlowAuth(
    tenant_id="your-tenant-id",
    client_id="your-client-id"
)
```

---

## 🔑 Azure Key Vault (Production)

### When to use
- Production environments where storing `client_secret` on disk is not acceptable
- Organizations that already centralize credentials in a corporate Key Vault
- CI/CD pipelines with Managed Identity (Azure DevOps, GitHub Actions with OIDC)

### Prerequisites

1. **Key Vault created** in Azure with the 3 SP secrets
2. **Role assigned:** `Key Vault Secrets User` for your user/SP on the vault
3. **Dependencies installed:**
   ```bash
   pip install fabricgov[keyvault]
   ```

### Creating the secrets

```bash
az keyvault secret set --vault-name MY-VAULT --name fabricgov-tenant-id     --value "<tenant-id>"
az keyvault secret set --vault-name MY-VAULT --name fabricgov-client-id     --value "<client-id>"
az keyvault secret set --vault-name MY-VAULT --name fabricgov-client-secret --value "<client-secret>"
```

> Secret names are flexible — the `fabricgov-*` defaults can be overridden via `--tenant-id-secret`, `--client-id-secret`, and `--client-secret-secret`.

### Configuring fabricgov

```bash
# With default names
fabricgov auth keyvault --vault-url https://my-vault.vault.azure.net/

# With custom names
fabricgov auth keyvault \
    --vault-url https://my-vault.vault.azure.net/ \
    --tenant-id-secret     pbi-tenant \
    --client-id-secret     pbi-client \
    --client-secret-secret pbi-secret
```

### How the vault is accessed

`DefaultAzureCredential` tries in order:

| Environment | Mechanism |
|---|---|
| Local development | `az login` (Azure CLI) |
| Azure VM / Container | Managed Identity |
| CI/CD | Env vars `AZURE_CLIENT_ID` + `AZURE_TENANT_ID` + `AZURE_CLIENT_SECRET` |

> 📘 [Key Vault quick start guide →](keyvault.md)

---

## 🔄 Comparison: all three methods

| Aspect | Service Principal | Device Flow | Key Vault |
|--------|:-----------------:|:-----------:|:---------:|
| **Setup** | App Registration | Zero | App Reg + Vault |
| **Credentials on disk** | ⚠️ `.env` file | ❌ None | ✅ Never |
| **Interaction** | Non-interactive | Browser | Non-interactive |
| **Automation / CI-CD** | ✅ | ❌ | ✅ |
| **Local development** | ⚠️ | ✅ | ✅ (with az login) |
| **Enterprise production** | ⚠️ | ❌ | ✅ Recommended |
| **Extra dependency** | None | None | `fabricgov[keyvault]` |

---

## 🛡️ Error Handling

### Service Principal Errors

#### `AuthenticationError: Invalid Tenant ID`
**Solution:** Check `FABRICGOV_TENANT_ID` in `.env`. Must be a valid GUID.

#### `UnauthorizedError: Invalid or expired token`
**Solution:** Verify `FABRICGOV_CLIENT_SECRET` is correct and not expired.

#### `ForbiddenError: Access denied`
**Solution:**
1. Verify the SP has `Tenant.Read.All` permission with **admin consent granted**
2. Confirm the SP is enabled in the Fabric Admin Portal
3. Wait up to 15 minutes for permissions to propagate

---

## 🔒 Security Best Practices

### Service Principal

✅ **DO:**
- Use `.env` and add it to `.gitignore`
- Rotate client secrets every 6–12 months
- Use Key Vault for production environments — `fabricgov auth keyvault`
- Apply the principle of least privilege

❌ **DON'T:**
- Commit credentials to Git
- Share secrets via email or chat
- Use the same SP across multiple environments
- Hardcode secrets in source code

---

## 📚 Additional Resources

- [Azure AD App Registrations](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app)
- [Power BI Service Principal](https://learn.microsoft.com/power-bi/developer/embedded/embed-service-principal)
- [Fabric Admin APIs](https://learn.microsoft.com/rest/api/power-bi/admin)
- [MSAL Python Documentation](https://msal-python.readthedocs.io/)
- [Azure Key Vault — fabricgov guide](keyvault.md)

---

**[← Back to README](../../README.md)** | **[Next: Collectors →](collectors.md)**
