# Guia de Autenticação

O **fabricgov** suporta dois modos de autenticação para acessar as APIs do Microsoft Fabric e Power BI:

1. **Service Principal** — autenticação não-interativa (recomendado para automação)
2. **Device Flow** — autenticação interativa via browser (recomendado para uso manual)

---

## 🔐 Service Principal (Automação)

### Quando usar
- Scripts automatizados
- CI/CD pipelines
- Notebooks agendados
- Ambientes sem interação humana

### Pré-requisitos

#### 1. Criar App Registration no Azure AD

1. Acesse o [Azure Portal](https://portal.azure.com)
2. Navegue até **Azure Active Directory** → **App registrations**
3. Clique em **New registration**
4. Configure:
   - **Name:** `fabricgov-automation` (ou qualquer nome)
   - **Supported account types:** "Accounts in this organizational directory only"
   - **Redirect URI:** deixe em branco
5. Clique em **Register**

#### 2. Copiar Credenciais

Após criar o App Registration:

- **Application (client) ID** → copie para `FABRICGOV_CLIENT_ID`
- **Directory (tenant) ID** → copie para `FABRICGOV_TENANT_ID`

#### 3. Criar Client Secret

1. No menu lateral, vá em **Certificates & secrets**
2. Clique em **New client secret**
3. Configure:
   - **Description:** `fabricgov-secret`
   - **Expires:** 24 months (ou conforme política da empresa)
4. Clique em **Add**
5. **IMPORTANTE:** Copie o **Value** imediatamente (só aparece uma vez) → `FABRICGOV_CLIENT_SECRET`

#### 4. Configurar Permissões da API

1. No menu lateral, vá em **API permissions**
2. Clique em **Add a permission**
3. Selecione **Power BI Service**
4. Escolha **Application permissions** (não "Delegated")
5. Adicione as seguintes permissões:
   - `Tenant.Read.All`
   - `Workspace.ReadWrite.All`
6. Clique em **Add permissions**
7. **CRÍTICO:** Clique em **Grant admin consent for [seu tenant]**
   - Só um admin do tenant pode fazer isso
   - Sem isso, o SP não funcionará

#### 5. Adicionar SP ao Grupo de Fabric Administrators

1. No [Portal do Power BI](https://app.powerbi.com)
2. Vá em **Settings** (engrenagem) → **Admin portal**
3. No menu lateral, **Tenant settings**
4. Role até **Admin API settings**
5. Habilite:
   - **Service principals can use Fabric APIs**
   - **Service principals can access read-only admin APIs**
6. Adicione o Service Principal ao grupo permitido (ou deixe "Apply to the entire organization")
7. Clique em **Apply**

#### 6. Adicionar SP ao Grupo de Administradores do Fabric

1. Ainda no **Admin portal**
2. Vá em **Capacity settings** → selecione sua capacidade
3. Em **Administrators**, adicione o App Registration (busque pelo nome ou client_id)
4. Salve as alterações

---

### Configuração no Projeto

#### Opção 1: Via arquivo `.env` (recomendado)

Crie um arquivo `.env` na raiz do projeto:
```env
FABRICGOV_TENANT_ID=00000000-0000-0000-0000-000000000000
FABRICGOV_CLIENT_ID=11111111-1111-1111-1111-111111111111
FABRICGOV_CLIENT_SECRET=seu-client-secret-aqui
```

**Uso no código:**
```python
from fabricgov.auth import ServicePrincipalAuth

# Lê automaticamente do .env
auth = ServicePrincipalAuth.from_env()
```

#### Opção 2: Via parâmetros diretos
```python
from fabricgov.auth import ServicePrincipalAuth

auth = ServicePrincipalAuth.from_params(
    tenant_id="00000000-0000-0000-0000-000000000000",
    client_id="11111111-1111-1111-1111-111111111111",
    client_secret="seu-client-secret-aqui"
)
```

#### Opção 3: Via variáveis de ambiente do sistema
```bash
export FABRICGOV_TENANT_ID="00000000-0000-0000-0000-000000000000"
export FABRICGOV_CLIENT_ID="11111111-1111-1111-1111-111111111111"
export FABRICGOV_CLIENT_SECRET="seu-client-secret-aqui"
```
```python
from fabricgov.auth import ServicePrincipalAuth

# Lê das variáveis de ambiente do sistema
auth = ServicePrincipalAuth.from_env()
```

---

### Exemplo Completo
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exceptions import ForbiddenError, UnauthorizedError

try:
    # Autentica via .env
    auth = ServicePrincipalAuth.from_env()
    
    # Usa em qualquer coletor
    collector = WorkspaceInventoryCollector(auth=auth)
    result = collector.collect()
    
    print(f"✓ Coletados {result['summary']['total_workspaces']} workspaces")
    
except UnauthorizedError as e:
    print(f"❌ Credenciais inválidas: {e.message}")
    
except ForbiddenError as e:
    print(f"❌ Sem permissões: {e.message}")
    print("   → Verifique se o SP está no grupo de Fabric Administrators")
```

---

## 🌐 Device Flow (Interativo)

### Quando usar
- Uso manual via terminal
- Desenvolvimento local
- Ambientes onde não é possível criar Service Principal
- Quando o usuário precisa autenticar com suas próprias credenciais

### Vantagens
- ✅ Não precisa de `tenant_id` nem `client_id` (usa padrões públicos)
- ✅ Não precisa criar App Registration no Azure AD
- ✅ Suporta MFA automaticamente
- ✅ Cache de token entre execuções (válido por ~1h)

### Requisitos
- Usuário deve ter permissões de **Fabric Administrator** no tenant
- Acesso a um browser para autenticação

---

### Configuração

**Nenhuma configuração necessária!** O Device Flow usa:
- Client ID público do Azure CLI
- Endpoint multi-tenant (`/common`) que descobre o tenant automaticamente

---

### Uso Básico
```python
from fabricgov.auth import DeviceFlowAuth

# Não precisa de parâmetros
auth = DeviceFlowAuth()

# Na primeira execução, exibe:
# ──────────────────────────────────────────────────────────────────
#   AUTENTICAÇÃO NECESSÁRIA
# ──────────────────────────────────────────────────────────────────
#   1. Acesse: https://microsoft.com/devicelogin
#   2. Digite o código: ABC12DEF
#   3. Autentique com sua conta Microsoft
# ──────────────────────────────────────────────────────────────────
#   Aguardando autenticação...
# ──────────────────────────────────────────────────────────────────

# Após autenticar no browser, o script continua automaticamente
```

---

### Uso Avançado (Tenant Específico)

Se você quiser forçar autenticação em um tenant específico:
```python
auth = DeviceFlowAuth(tenant_id="seu-tenant-id")
```

Se você tiver um App Registration próprio com permissões customizadas:
```python
auth = DeviceFlowAuth(
    tenant_id="seu-tenant-id",
    client_id="seu-client-id"
)
```

---

### Exemplo Completo
```python
from fabricgov.auth import DeviceFlowAuth
from fabricgov.collectors import WorkspaceInventoryCollector

# Autentica via Device Flow
auth = DeviceFlowAuth()

# Usa em qualquer coletor
collector = WorkspaceInventoryCollector(
    auth=auth,
    progress_callback=lambda msg: print(msg)
)

result = collector.collect()

print(f"\n✓ Coletados {result['summary']['total_workspaces']} workspaces")
print(f"✓ Total de itens: {result['summary']['total_items']}")
```

**Output:**
```
──────────────────────────────────────────────────────────────────
  AUTENTICAÇÃO NECESSÁRIA
──────────────────────────────────────────────────────────────────
  1. Acesse: https://microsoft.com/devicelogin
  2. Digite o código: ABC12DEF
  3. Autentique com sua conta Microsoft
──────────────────────────────────────────────────────────────────
  Aguardando autenticação...
──────────────────────────────────────────────────────────────────

[16:33:36] Listando workspaces do tenant...
[16:33:36] Encontrados 302 workspaces
...
```

---

### Cache de Token

O MSAL mantém cache de token em memória. Isso significa:

- **Primeira execução:** pede autenticação
- **Execuções seguintes (mesma sessão Python):** usa token em cache
- **Nova sessão Python:** pede autenticação novamente

O token tem validade de ~1 hora. Após expirar, o Device Flow é reiniciado automaticamente.

---

## 🔄 Comparação: Service Principal vs Device Flow

| Aspecto | Service Principal | Device Flow |
|---------|-------------------|-------------|
| **Setup** | Requer App Registration + permissões | Zero configuração |
| **Credenciais** | client_id + client_secret | Nenhuma credencial necessária |
| **Interação** | Não-interativa | Interativa (browser) |
| **MFA** | N/A | Suportado automaticamente |
| **Automação** | ✅ Ideal para CI/CD | ❌ Não recomendado |
| **Desenvolvimento local** | ⚠️ Requer secrets | ✅ Perfeito |
| **Permissões** | App-level (Tenant.Read.All) | User-level (delegated) |
| **Auditoria** | Service Principal name | Nome do usuário |

---

## 🛡️ Tratamento de Erros

### Erros comuns do Service Principal

#### 1. `AuthenticationError: Tenant ID inválido`
```
Falha ao inicializar autenticação.
Tenant ID inválido ou inacessível: invalid-tenant
```

**Solução:** Verifique o `FABRICGOV_TENANT_ID` no `.env`. Deve ser um GUID válido do seu tenant.

---

#### 2. `UnauthorizedError: Token inválido ou expirado`
```
[401] Token inválido ou expirado. Verifique as credenciais.
Endpoint: /v1.0/myorg/admin/groups
```

**Solução:** Verifique:
- `FABRICGOV_CLIENT_SECRET` está correto
- O secret não expirou (Azure AD → App registrations → Certificates & secrets)

---

#### 3. `ForbiddenError: Acesso negado`
```
[403] Acesso negado. O Service Principal precisa de permissões de Fabric Administrator.
Endpoint: /v1.0/myorg/admin/groups
```

**Solução:** 
1. Verifique se o SP tem permissões `Tenant.Read.All` **concedidas via admin consent**
2. Confirme que o SP está no grupo de **Fabric Administrators**
3. Aguarde até 15 minutos para as permissões propagarem

---

### Erros comuns do Device Flow

#### 1. Device Flow expirou
```
AuthenticationError: Falha na autenticação via Device Flow.
Erro: authorization_pending
Detalhe: Flow expirou sem autenticação
```

**Solução:** O código expira em 15 minutos. Execute novamente e autentique mais rápido.

---

#### 2. Usuário sem permissões
```
[403] Acesso negado.
```

**Solução:** O usuário que autenticou precisa ser **Fabric Administrator** no tenant.

---

## 🔒 Boas Práticas de Segurança

### Para Service Principal

✅ **FAÇA:**
- Use `.env` e adicione ao `.gitignore`
- Rotacione client secrets a cada 6-12 meses
- Use Key Vault para ambientes de produção
- Limite permissões ao mínimo necessário
- Monitore uso do SP via Azure AD logs

❌ **NÃO FAÇA:**
- Commitar credenciais no Git
- Compartilhar secrets via email/chat
- Usar o mesmo SP em múltiplos ambientes
- Deixar secrets em código hardcoded

---

### Para Device Flow

✅ **FAÇA:**
- Use em ambientes de desenvolvimento
- Revogue sessões antigas periodicamente
- Monitore acessos via Fabric logs

❌ **NÃO FAÇA:**
- Usar em automação/CI-CD
- Compartilhar tokens entre usuários
- Deixar sessões abertas em máquinas compartilhadas

---

## 📚 Recursos Adicionais

- [Azure AD App Registrations](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app)
- [Power BI Service Principal](https://learn.microsoft.com/power-bi/developer/embedded/embed-service-principal)
- [Fabric Admin APIs](https://learn.microsoft.com/rest/api/power-bi/admin)
- [MSAL Python Documentation](https://msal-python.readthedocs.io/)

---

**[← Voltar ao README](../README.md)** | **[Próximo: Coletores →](collectors.md)**