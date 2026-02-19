# Testes Manuais

Scripts de teste para execução manual durante o desenvolvimento da biblioteca fabricgov.

## Scripts disponíveis:

### `test_inventory_sp.py`
Coleta inventário completo via **Service Principal** (autenticação não-interativa).

**Uso:**
```bash
poetry run python tests/manual/test_inventory_sp.py
```

**Requisitos:**
- `.env` configurado com `FABRICGOV_TENANT_ID`, `FABRICGOV_CLIENT_ID`, `FABRICGOV_CLIENT_SECRET`
- Service Principal com permissões de **Fabric Administrator**

**Output:**
- Pasta `output/YYYYMMDD_HHMMSS/` com arquivos JSON/CSV
- `log.txt` com progresso completo da execução

---

### `test_inventory_device_flow.py`
Coleta inventário via **Device Flow** (autenticação interativa no browser).

**Uso:**
```bash
poetry run python tests/manual/test_inventory_device_flow.py
```

**Requisitos:**
- Usuário com permissões de **Fabric Administrator**
- Browser disponível para autenticação

**Comportamento:**
- Primeira execução: pede autenticação via URL + código
- Execuções seguintes: usa token em cache (válido por ~1h)

---

### `test_errors_sp_errada.py`
Testa tratamento de erros com **credenciais inválidas** no Service Principal.

**Uso:**
```bash
poetry run python tests/manual/test_errors_sp_errada.py
```

**Valida:**
- Captura de `AuthenticationError` quando tenant_id/client_id/client_secret estão incorretos
- Mensagens de erro claras e acionáveis

---

### `test_errors_sp_sem_permissao.py`
Testa tratamento de erros quando Service Principal **não tem permissões de Admin**.

**Uso:**
```bash
poetry run python tests/manual/test_errors_sp_sem_permissao.py
```

**Valida:**
- Captura de `ForbiddenError` (403) ao tentar acessar APIs Admin
- Mensagem indicando necessidade de permissões de Fabric Administrator

---

## Configuração do `.env`

Crie um arquivo `.env` na raiz do projeto:
```env
FABRICGOV_TENANT_ID=seu-tenant-id-aqui
FABRICGOV_CLIENT_ID=seu-client-id-aqui
FABRICGOV_CLIENT_SECRET=seu-client-secret-aqui
```

**Como obter as credenciais:**
1. Acesse o [Azure Portal](https://portal.azure.com)
2. Navegue até **Azure Active Directory** → **App registrations**
3. Crie um novo registro ou use existente
4. Copie o **Application (client) ID** e **Directory (tenant) ID**
5. Em **Certificates & secrets**, crie um novo **Client secret**

**Permissões necessárias:**
- Power BI Service: `Tenant.Read.All` (Application permission)
- Fabric: `Workspace.ReadWrite.All` (Application permission)
- O SP precisa estar no grupo **Fabric Administrators** do tenant

---

## Output dos testes

Todos os testes de inventário geram output em:
```
output/
└── YYYYMMDD_HHMMSS/
    ├── log.txt                     # Log completo da execução
    ├── summary.json                # Resumo consolidado
    ├── workspaces.json (ou .csv)   # Metadados dos workspaces
    ├── reports.json (ou .csv)      # Reports coletados
    ├── datasets.json (ou .csv)     # Datasets coletados
    └── ...                         # Outros tipos de artefatos
```

O formato (JSON ou CSV) é configurável no script.