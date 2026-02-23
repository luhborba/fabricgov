# Guia de Coletores

Os **coletores** são responsáveis por buscar dados específicos das APIs do Microsoft Fabric e Power BI. Cada coletor herda comportamentos comuns do `BaseCollector` (retry, paginação, rate limiting) e implementa lógica específica para seu domínio.

---

## 📦 Coletores Disponíveis

### ✅ WorkspaceInventoryCollector
### ✅ WorkspaceAccessCollector
### ✅ ReportAccessCollector

---

## 🔍 WorkspaceInventoryCollector

### O que coleta

- **Workspaces:** metadados de todos os workspaces do tenant
- **27+ tipos de artefatos:**
  - `datasets` — Semantic Models / Datasets
  - `reports` — Power BI Reports
  - `dashboards` — Power BI Dashboards
  - `dataflows` — Dataflows Gen1 e Gen2
  - `datamarts` — Datamarts
  - `lakehouses` — Lakehouses
  - `warehouses` — Data Warehouses
  - `notebooks` — Notebooks
  - `sparkJobDefinitions` — Spark Job Definitions
  - `mlModels` — ML Models
  - `mlExperiments` — ML Experiments
  - `kqlDatabases` — KQL Databases
  - `kqlQuerysets` — KQL Querysets
  - `eventstreams` — Eventstreams
  - `reflex` — Reflex
  - `semanticModels` — Semantic Models
  - `sqlEndpoints` — SQL Endpoints
  - `mirroredDatabases` — Mirrored Databases
  - `mirroredWarehouses` — Mirrored Warehouses
  - `graphqlApis` — GraphQL APIs
  - `sqlDatabases` — SQL Databases
  - `variableLibraries` — Variable Libraries
  - `paginatedReports` — Paginated Reports
  - `deploymentPipelines` — Deployment Pipelines
  - `workbooks` — Excel Workbooks
- **Datasources:**
  - `datasourceInstances` — Datasources configurados
  - `misconfiguredDatasourceInstances` — Datasources com erro de configuração

---

### Como funciona

**Fluxo interno:**

1. **GET** `/v1.0/myorg/admin/groups` → Lista todos os workspace IDs
2. **Divide em lotes de 100** (limite da API de scan)
3. Para cada lote:
   - **POST** `/v1.0/myorg/admin/workspaces/getInfo` → Inicia scan assíncrono
   - **Polling** em `/scanStatus/{scanId}` até status = `Succeeded`
   - **GET** `/scanResult/{scanId}` → Coleta resultado
4. **Agrega** todos os resultados e extrai artefatos por tipo

---

### Parâmetros do Construtor
```python
WorkspaceInventoryCollector(
    auth: AuthProvider,                          # Obrigatório
    progress_callback: Callable[[str], None] | None = None,
    poll_interval: int = 5,                      # Padrão: 5 segundos
    max_poll_time: int = 600,                    # Padrão: 10 minutos
    **kwargs                                     # Passa para BaseCollector
)
```

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `auth` | `AuthProvider` | ServicePrincipalAuth ou DeviceFlowAuth |
| `progress_callback` | `Callable[[str], None]` | Função chamada a cada update de progresso |
| `poll_interval` | `int` | Segundos entre verificações de status do scan |
| `max_poll_time` | `int` | Timeout máximo em segundos por scan |

**Parâmetros herdados do BaseCollector** (via `**kwargs`):
- `timeout` — timeout HTTP em segundos (padrão: 30)
- `max_retries` — tentativas em caso de erro transiente (padrão: 3)
- `retry_delay` — delay base entre retries (padrão: 1.0s)
- `request_delay` — delay entre requests sucessivos (padrão: 0.1s)

---

### Uso Básico
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector

auth = ServicePrincipalAuth.from_env()

collector = WorkspaceInventoryCollector(auth=auth)
result = collector.collect()

print(f"Total de workspaces: {result['summary']['total_workspaces']}")
print(f"Total de itens: {result['summary']['total_items']}")
```

---

### Uso com Progress Callback
```python
from datetime import datetime

def progress(msg: str):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

collector = WorkspaceInventoryCollector(
    auth=auth,
    progress_callback=progress
)

result = collector.collect()
```

**Output:**
```
[16:33:36] Listando workspaces do tenant...
[16:33:36] Encontrados 302 workspaces
[16:33:36] Dividido em 4 lote(s) de até 100 workspaces

--- Lote 1/4 (100 workspaces) ---
[16:33:36] Iniciando scan do lote 1/4...
[16:33:37] Scan iniciado (id: a7590fb0-...)
[16:33:42] Lote 1/4 - Status: Succeeded (5s)
[16:33:42] Coletando resultado do scan...
[16:33:42] ✓ Lote 1/4 concluído: 100 workspaces
...
[16:33:59] ✓ Coleta concluída: 302 workspaces, 1367 itens em 23.8s
```

---

### Estrutura do Output
```python
{
  "workspaces": [
    {
      "id": "workspace-guid",
      "name": "workspace-name",
      "description": "...",
      "type": "Workspace",
      "state": "Active",
      "isOnDedicatedCapacity": true,
      "capacityId": "capacity-guid",
      ...
    }
  ],
  "datasets": [
    {
      "id": "dataset-guid",
      "name": "dataset-name",
      "configuredBy": "user@domain.com",
      "workspace_id": "workspace-guid",
      "workspace_name": "workspace-name",
      ...
    }
  ],
  "reports": [...],
  "dashboards": [...],
  // ... outros tipos de artefatos
  "datasourceInstances": [...],
  "misconfiguredDatasourceInstances": [...],
  "summary": {
    "total_workspaces": 302,
    "total_items": 1367,
    "items_by_type": {
      "reports": 777,
      "datasets": 506,
      "dashboards": 65,
      "warehouses": 11,
      "dataflows": 6,
      "datamarts": 2,
      // ... outros tipos com count = 0 omitidos
    },
    "scan_duration_seconds": 23.82,
    "batches_processed": 4
  }
}
```

**Campos adicionados em cada artefato:**
- `workspace_id` — ID do workspace que contém o artefato
- `workspace_name` — Nome do workspace (para rastreabilidade)

---

### Performance

**Tenant de referência (302 workspaces):**
- **Tempo de execução:** ~24 segundos
- **Lotes processados:** 4 (100 + 100 + 100 + 2)
- **Itens coletados:** 1367 artefatos
- **Rate limiting:** Nenhum throttling observado

**Fatores que impactam performance:**
- Número de workspaces no tenant
- Tamanho dos workspaces (quantidade de artefatos)
- Latência de rede
- Carga da API da Microsoft

---

### Tratamento de Erros

#### Erro 403: Sem permissões
```python
from fabricgov.exceptions import ForbiddenError

try:
    result = collector.collect()
except ForbiddenError as e:
    print(f"❌ {e.message}")
    print(f"   Endpoint: {e.endpoint}")
    print("   → Verifique se o SP tem permissões de Fabric Administrator")
```

#### Timeout de scan

Se um scan demorar mais de `max_poll_time` (padrão: 10 minutos):
```python
from fabricgov.exceptions import TimeoutError

try:
    collector = WorkspaceInventoryCollector(
        auth=auth,
        max_poll_time=1800  # 30 minutos
    )
    result = collector.collect()
except TimeoutError as e:
    print(f"❌ Scan excedeu timeout: {str(e)}")
```

#### Scan falhou

Se a API retornar status `Failed`:
```python
try:
    result = collector.collect()
except RuntimeError as e:
    print(f"❌ Scan falhou: {str(e)}")
```

---

### Limitações Conhecidas

1. **Batching obrigatório:** API aceita no máximo 100 workspaces por scan
2. **Tempo de scan:** Pode levar até 5-10s por lote de 100 workspaces
3. **Dados em cache:** O scan retorna snapshot do momento — não é real-time
4. **Rate limiting:** Múltiplos scans simultâneos podem resultar em throttling

---

### Casos de Uso

#### 1. Inventário completo para governança
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exporters import FileExporter

auth = ServicePrincipalAuth.from_env()
collector = WorkspaceInventoryCollector(auth=auth)
result = collector.collect()

# Exporta para análise
exporter = FileExporter(format="csv", output_dir="output")
exporter.export(result, log_messages=[])
```

#### 2. Identificar workspaces órfãos
```python
result = collector.collect()

orphaned = [
    ws for ws in result['workspaces']
    if ws.get('isOrphaned') == True
]

print(f"Workspaces órfãos: {len(orphaned)}")
for ws in orphaned:
    print(f"  - {ws['name']} ({ws['id']})")
```

#### 3. Listar todos os datasets em capacidade específica
```python
capacity_id = "seu-capacity-id"

result = collector.collect()

datasets_in_capacity = [
    ds for ds in result['datasets']
    if any(
        ws['id'] == ds['workspace_id'] and ws.get('capacityId') == capacity_id
        for ws in result['workspaces']
    )
]

print(f"Datasets na capacidade {capacity_id}: {len(datasets_in_capacity)}")
```

#### 4. Detectar datasources com erro de configuração
```python
result = collector.collect()

misconfigured = result['misconfiguredDatasourceInstances']

if misconfigured:
    print(f"⚠️  {len(misconfigured)} datasources com erro de configuração:")
    for ds in misconfigured:
        print(f"  - {ds.get('datasourceType')}: {ds.get('datasourceInstanceId')}")
```

---

## 🔐 WorkspaceAccessCollector

Extrai roles de acesso (Admin, Member, Contributor, Viewer) em workspaces via Power BI Admin API.

### O que coleta

- **Roles em workspaces:** Admin, Member, Contributor, Viewer
- **Usuários:** email, identifier, principal type
- **Service Principals:** Apps com acesso aos workspaces

**Filtragem automática:**
- Personal Workspaces são ignorados (não suportam API de usuários)

---

### Como funciona

**Pré-requisito:**
Requer o resultado do `WorkspaceInventoryCollector` para obter a lista de workspace IDs.

**Fluxo:**
1. Recebe o `inventory_result` do WorkspaceInventoryCollector
2. Filtra Personal Workspaces (nome começa com "PersonalWorkspace")
3. Para cada workspace:
   - **GET** `/v1.0/myorg/admin/groups/{groupId}/users`
   - Coleta lista de usuários e roles
   - Se detectar **429 Rate Limit**: pausa 30s e tenta novamente (até 5x)
4. Agrega resultados e gera summary

---

### Parâmetros do Construtor
```python
WorkspaceAccessCollector(
    auth: AuthProvider,                          # Obrigatório
    inventory_result: dict[str, Any],            # Obrigatório
    progress_callback: Callable[[str], None] | None = None,
    **kwargs                                     # Passa para BaseCollector
)
```

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `auth` | `AuthProvider` | ServicePrincipalAuth ou DeviceFlowAuth |
| `inventory_result` | `dict` | Resultado do WorkspaceInventoryCollector.collect() |
| `progress_callback` | `Callable` | Função chamada a cada update de progresso |

---

### Uso Básico
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import (
    WorkspaceInventoryCollector,
    WorkspaceAccessCollector
)

auth = ServicePrincipalAuth.from_env()

# Passo 1: Coleta inventário
inventory_collector = WorkspaceInventoryCollector(auth=auth)
inventory_result = inventory_collector.collect()

# Passo 2: Coleta acessos
access_collector = WorkspaceAccessCollector(
    auth=auth,
    inventory_result=inventory_result
)
access_result = access_collector.collect()

print(f"Total de acessos: {access_result['summary']['total_access_entries']}")
print(f"Workspaces processados: {access_result['summary']['workspaces_processed']}")
```

---

### Estrutura do Output
```python
{
  "workspace_access": [
    {
      "workspace_id": "abc-123",
      "workspace_name": "Marketing Analytics",
      "user_email": "user@company.com",
      "user_identifier": "user-guid",
      "principal_type": "User",  # ou "App" (Service Principal)
      "role": "Admin"  # Admin, Member, Contributor, Viewer
    }
  ],
  "workspace_access_errors": [
    {
      "workspace_id": "xyz-789",
      "workspace_name": "Failed Workspace",
      "error_type": "TooManyRequestsError",
      "error_message": "Rate limit persistiu após 5 tentativas",
      "status_code": 429
    }
  ],
  "summary": {
    "total_workspaces": 302,
    "personal_workspaces_skipped": 120,
    "workspaces_processed": 182,
    "workspaces_with_users": 88,
    "total_access_entries": 294,
    "users_count": 48,
    "service_principals_count": 7,
    "roles_breakdown": {
      "Admin": 263,
      "Member": 9,
      "Viewer": 15,
      "Contributor": 7
    },
    "rate_limit_pauses": 15,
    "errors_count": 2
  }
}
```

---

### Performance

**Tenant de referência (302 workspaces):**
- **Workspaces filtrados:** 182 (120 Personal Workspaces ignorados)
- **Tempo de execução:** ~5-10 minutos
- **Acessos coletados:** 294 entradas
- **Rate limit pauses:** 15 pausas de 30s

---

### Limitações e Rate Limiting

#### Rate Limit da API

A API `GET /admin/groups/{groupId}/users` tem **limite de ~200 requests/hora** (não documentado oficialmente).

**Comportamento observado:**
- Após ~200 requests, a API retorna `429 Too Many Requests`
- O limite parece ser uma **janela deslizante**, não fixo de 1 hora
- Pausar 30s e tentar novamente geralmente funciona

**Estratégia implementada:**
1. Ao detectar `429`, pausa 30 segundos
2. Tenta novamente o mesmo workspace (até 5 tentativas)
3. Se após 5 pausas ainda der `429`, registra como erro

**Estimativa de tempo:**
- 100 workspaces: ~3-5 minutos
- 200 workspaces: ~7-12 minutos (com pausas)
- 500 workspaces: ~20-40 minutos (com múltiplas pausas)

---

#### Personal Workspaces

**Personal Workspaces não suportam a API de usuários.**

**Identificação:**
- Nome do workspace começa com `"PersonalWorkspace "`
- Exemplo: `"PersonalWorkspace John Doe (john@company.com)"`

**Comportamento:**
- Retornam `404 Not Found` ao tentar buscar usuários
- São **automaticamente filtrados** pelo coletor antes de fazer chamadas

**Exemplo de log:**
```
Total de workspaces: 302
Personal Workspaces ignorados: 120
Workspaces a processar: 182
```

---

### Tratamento de Erros

#### Rate Limit (429)
```python
# O coletor lida automaticamente com 429
# Pausa 30s e tenta novamente até 5x

# Se esgotar tentativas, registra em workspace_access_errors
{
  "workspace_id": "...",
  "error_type": "TooManyRequestsError",
  "status_code": 429
}
```

#### Workspace não encontrado (404)

Raro, mas pode acontecer se workspace foi deletado entre o inventory e a coleta de access.
```python
{
  "workspace_id": "...",
  "error_type": "NotFoundError",
  "status_code": 404
}
```

---

### Casos de Uso

#### 1. Auditoria de acessos privilegiados
```python
result = access_collector.collect()

admins = [
    access for access in result['workspace_access']
    if access['role'] == 'Admin'
]

print(f"Total de Admins: {len(admins)}")
for admin in admins:
    print(f"  {admin['user_email']} → {admin['workspace_name']}")
```

#### 2. Identificar Service Principals com acesso
```python
result = access_collector.collect()

service_principals = [
    access for access in result['workspace_access']
    if access['principal_type'] == 'App'
]

print(f"Service Principals com acesso: {len(service_principals)}")
```

#### 3. Workspaces com apenas 1 Admin (risco de órfão)
```python
from collections import defaultdict

result = access_collector.collect()

workspaces_admins = defaultdict(list)
for access in result['workspace_access']:
    if access['role'] == 'Admin':
        workspaces_admins[access['workspace_id']].append(access['user_email'])

at_risk = {
    ws_id: admins for ws_id, admins in workspaces_admins.items()
    if len(admins) == 1
}

print(f"⚠️  {len(at_risk)} workspaces com apenas 1 Admin (risco de órfão)")
```

---

## 📄 ReportAccessCollector

Extrai permissões de acesso (Owner, Read, ReadWrite, etc.) em reports via Power BI Admin API.

### O que coleta

- **Permissões em reports:** Owner, Read, ReadWrite, ReadCopy, ReadReshare, ReadExplore
- **Usuários:** email, identifier, principal type
- **Service Principals:** Apps com acesso aos reports

**Filtragem automática:**
- Reports em Personal Workspaces são ignorados (não suportam API de usuários)

---

### Como funciona

**Pré-requisito:**
Requer o resultado do `WorkspaceInventoryCollector` para obter a lista de report IDs.

**Fluxo:**
1. Recebe o `inventory_result` do WorkspaceInventoryCollector
2. Filtra reports de Personal Workspaces (workspace_name começa com "PersonalWorkspace")
3. Para cada report:
   - **GET** `/v1.0/myorg/admin/reports/{reportId}/users`
   - Coleta lista de usuários e permissões
   - Se detectar **429 Rate Limit**: pausa 30s e tenta novamente (até 5x)
4. Agrega resultados e gera summary

---

### Parâmetros do Construtor
```python
ReportAccessCollector(
    auth: AuthProvider,                          # Obrigatório
    inventory_result: dict[str, Any],            # Obrigatório
    progress_callback: Callable[[str], None] | None = None,
    **kwargs                                     # Passa para BaseCollector
)
```

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `auth` | `AuthProvider` | ServicePrincipalAuth ou DeviceFlowAuth |
| `inventory_result` | `dict` | Resultado do WorkspaceInventoryCollector.collect() |
| `progress_callback` | `Callable` | Função chamada a cada update de progresso |

---

### Uso Básico
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import (
    WorkspaceInventoryCollector,
    ReportAccessCollector
)

auth = ServicePrincipalAuth.from_env()

# Passo 1: Coleta inventário
inventory_collector = WorkspaceInventoryCollector(auth=auth)
inventory_result = inventory_collector.collect()

# Passo 2: Coleta acessos de reports
access_collector = ReportAccessCollector(
    auth=auth,
    inventory_result=inventory_result
)
access_result = access_collector.collect()

print(f"Total de acessos: {access_result['summary']['total_access_entries']}")
print(f"Reports processados: {access_result['summary']['reports_processed']}")
```

---

### Estrutura do Output
```python
{
  "report_access": [
    {
      "report_id": "report-123",
      "report_name": "Sales Dashboard",
      "workspace_id": "abc-123",
      "workspace_name": "Marketing Analytics",
      "user_email": "user@company.com",
      "user_identifier": "user-guid",
      "principal_type": "User",
      "permission": "Owner"  # Owner, Read, ReadWrite, ReadCopy, ReadReshare, ReadExplore
    }
  ],
  "report_access_errors": [...],
  "summary": {
    "total_reports": 777,
    "personal_workspaces_reports_skipped": 150,
    "reports_processed": 627,
    "reports_with_users": 400,
    "total_access_entries": 4363,
    "users_count": 54,
    "service_principals_count": 7,
    "permissions_breakdown": {
      "Owner": 3945,
      "ReadReshare": 15,
      "ReadCopy": 164,
      "Read": 230,
      "ReadReshareExplore": 2,
      "ReadWrite": 7
    },
    "rate_limit_pauses": 25,
    "errors_count": 3
  }
}
```

---

### Performance

**Tenant de referência (777 reports):**
- **Reports filtrados:** 627 (150 em Personal Workspaces ignorados)
- **Tempo de execução:** ~15-30 minutos
- **Acessos coletados:** 4363 entradas
- **Rate limit pauses:** 25 pausas de 30s

---

### Limitações e Rate Limiting

#### Rate Limit da API

A API `GET /admin/reports/{reportId}/users` tem **limite de ~200 requests/hora** (não documentado oficialmente).

**Mesma estratégia do WorkspaceAccessCollector:**
- Ao detectar `429`, pausa 30 segundos
- Tenta novamente até 5 vezes
- Registra como erro apenas se esgotar tentativas

**Estimativa de tempo:**
- 200 reports: ~5-10 minutos
- 500 reports: ~15-25 minutos (com pausas)
- 1000 reports: ~30-60 minutos (com múltiplas pausas)

---

#### Reports em Personal Workspaces

**Reports em Personal Workspaces não suportam a API de usuários.**

**Comportamento:**
- Retornam `404 Not Found` ou `429 Too Many Requests`
- São **automaticamente filtrados** pelo coletor antes de fazer chamadas

**Exemplo de log:**
```
Total de reports: 777
Reports em Personal Workspaces ignorados: 150
Reports a processar: 627
```

---

### Casos de Uso

#### 1. Reports compartilhados externamente
```python
result = access_collector.collect()

external_shares = [
    access for access in result['report_access']
    if not access['user_email'].endswith('@yourcompany.com')
]

print(f"Reports compartilhados externamente: {len(external_shares)}")
```

#### 2. Reports com muitos Owners (má prática)
```python
from collections import defaultdict

result = access_collector.collect()

report_owners = defaultdict(list)
for access in result['report_access']:
    if access['permission'] == 'Owner':
        report_owners[access['report_id']].append(access['user_email'])

too_many_owners = {
    rpt_id: owners for rpt_id, owners in report_owners.items()
    if len(owners) > 3
}

print(f"⚠️  {len(too_many_owners)} reports com mais de 3 Owners")
```

---

## 📊 DatasetAccessCollector

Extrai permissões de acesso (Read, ReadWrite, Build, etc.) em datasets via Power BI Admin API.

### O que coleta

- **Permissões em datasets:** Read, ReadWrite, Build, Reshare
- **Usuários:** email, identifier, principal type
- **Service Principals:** Apps com acesso aos datasets

**Filtragem automática:**
- Datasets em Personal Workspaces são ignorados (não suportam API de usuários)

---

### Como funciona

**Pré-requisito:**
Requer o resultado do `WorkspaceInventoryCollector` para obter a lista de dataset IDs.

**Fluxo:**
1. Recebe o `inventory_result` do WorkspaceInventoryCollector
2. Filtra datasets de Personal Workspaces (workspace_name começa com "PersonalWorkspace")
3. Para cada dataset:
   - **GET** `/v1.0/myorg/admin/datasets/{datasetId}/users`
   - Coleta lista de usuários e permissões
   - Se detectar **429 Rate Limit**: pausa 30s e tenta novamente (até 5x)
4. Agrega resultados e gera summary

---

### Parâmetros do Construtor
```python
DatasetAccessCollector(
    auth: AuthProvider,                          # Obrigatório
    inventory_result: dict[str, Any],            # Obrigatório
    progress_callback: Callable[[str], None] | None = None,
    checkpoint_file: str | Path | None = None,   # Opcional (habilita checkpoint)
    **kwargs                                     # Passa para BaseCollector
)
```

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `auth` | `AuthProvider` | ServicePrincipalAuth ou DeviceFlowAuth |
| `inventory_result` | `dict` | Resultado do WorkspaceInventoryCollector.collect() |
| `progress_callback` | `Callable` | Função chamada a cada update de progresso |
| `checkpoint_file` | `str\|Path` | Caminho do checkpoint (habilita modo incremental) |

---

### Uso Básico
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import (
    WorkspaceInventoryCollector,
    DatasetAccessCollector
)

auth = ServicePrincipalAuth.from_env()

# Passo 1: Coleta inventário
inventory_collector = WorkspaceInventoryCollector(auth=auth)
inventory_result = inventory_collector.collect()

# Passo 2: Coleta acessos de datasets
access_collector = DatasetAccessCollector(
    auth=auth,
    inventory_result=inventory_result,
    checkpoint_file="output/checkpoint_dataset_access.json"
)
access_result = access_collector.collect()

print(f"Total de acessos: {access_result['summary']['total_access_entries']}")
print(f"Datasets processados: {access_result['summary']['datasets_processed']}")
```

---

### Estrutura do Output
```python
{
  "dataset_access": [
    {
      "dataset_id": "dataset-123",
      "dataset_name": "Sales Data",
      "workspace_id": "abc-123",
      "workspace_name": "Marketing Analytics",
      "user_email": "user@company.com",
      "user_identifier": "user-guid",
      "principal_type": "User",
      "permission": "Read"  # Read, ReadWrite, Build, Reshare
    }
  ],
  "dataset_access_errors": [...],
  "summary": {
    "total_datasets": 506,
    "personal_workspaces_datasets_skipped": 180,
    "datasets_processed": 326,
    "datasets_with_users": 250,
    "total_access_entries": 1200,
    "users_count": 80,
    "service_principals_count": 5,
    "permissions_breakdown": {
      "Read": 800,
      "ReadWrite": 300,
      "Build": 80,
      "Reshare": 20
    },
    "errors_count": 2
  }
}
```

---

### Performance

**Tenant de referência (506 datasets):**
- **Datasets filtrados:** 326 (180 em Personal Workspaces ignorados)
- **Tempo de execução:** ~10-20 minutos (depende de rate limiting)
- **Acessos coletados:** ~1200 entradas
- **Checkpoint interval:** a cada 100 datasets

---

### Limitações e Rate Limiting

#### Rate Limit da API

A API `GET /admin/datasets/{datasetId}/users` tem **limite de ~200 requests/hora** (não documentado oficialmente).

**Mesma estratégia dos outros access collectors:**
- Ao detectar `429`, salva checkpoint e encerra
- Retoma de onde parou em próxima execução

**Estimativa de tempo:**
- 200 datasets: ~10 minutos (pode bater rate limit)
- 500 datasets: ~30-60 minutos (com pausas)

---

#### Datasets em Personal Workspaces

**Datasets em Personal Workspaces não suportam a API de usuários.**

**Comportamento:**
- Retornam `404 Not Found` ou `429 Too Many Requests`
- São **automaticamente filtrados** pelo coletor antes de fazer chamadas

**Exemplo de log:**
```
Total de datasets: 506
Datasets em Personal Workspaces ignorados: 180
A processar nesta execução: 326
```

---

### Casos de Uso

#### 1. Datasets compartilhados externamente
```python
result = access_collector.collect()

external_shares = [
    access for access in result['dataset_access']
    if not access['user_email'].endswith('@yourcompany.com')
]

print(f"Datasets compartilhados externamente: {len(external_shares)}")
```

#### 2. Datasets com permissão Build (alto privilégio)
```python
result = access_collector.collect()

build_permissions = [
    access for access in result['dataset_access']
    if access['permission'] == 'Build'
]

print(f"⚠️  {len(build_permissions)} usuários com permissão Build")
```

---

## 🌊 DataflowAccessCollector

Extrai permissões de acesso em dataflows via Power BI Admin API.

### O que coleta

- **Permissões em dataflows:** Owner, User
- **Usuários:** email, identifier, principal type
- **Service Principals:** Apps com acesso aos dataflows

**Filtragem automática:**
- Dataflows em Personal Workspaces são ignorados (não suportam API de usuários)

---

### Como funciona

**Pré-requisito:**
Requer o resultado do `WorkspaceInventoryCollector` para obter a lista de dataflow IDs.

**Fluxo:**
1. Recebe o `inventory_result` do WorkspaceInventoryCollector
2. Filtra dataflows de Personal Workspaces (workspace_name começa com "PersonalWorkspace")
3. Para cada dataflow:
   - **GET** `/v1.0/myorg/admin/dataflows/{dataflowId}/users`
   - Coleta lista de usuários e permissões
   - Se detectar **429 Rate Limit**: salva checkpoint e encerra
4. Agrega resultados e gera summary

---

### Parâmetros do Construtor
```python
DataflowAccessCollector(
    auth: AuthProvider,                          # Obrigatório
    inventory_result: dict[str, Any],            # Obrigatório
    progress_callback: Callable[[str], None] | None = None,
    checkpoint_file: str | Path | None = None,   # Opcional (habilita checkpoint)
    **kwargs                                     # Passa para BaseCollector
)
```

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `auth` | `AuthProvider` | ServicePrincipalAuth ou DeviceFlowAuth |
| `inventory_result` | `dict` | Resultado do WorkspaceInventoryCollector.collect() |
| `progress_callback` | `Callable` | Função chamada a cada update de progresso |
| `checkpoint_file` | `str\|Path` | Caminho do checkpoint (habilita modo incremental) |

---

### Uso Básico
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import (
    WorkspaceInventoryCollector,
    DataflowAccessCollector
)

auth = ServicePrincipalAuth.from_env()

# Passo 1: Coleta inventário
inventory_collector = WorkspaceInventoryCollector(auth=auth)
inventory_result = inventory_collector.collect()

# Passo 2: Coleta acessos de dataflows
access_collector = DataflowAccessCollector(
    auth=auth,
    inventory_result=inventory_result,
    checkpoint_file="output/checkpoint_dataflow_access.json"
)
access_result = access_collector.collect()

print(f"Total de acessos: {access_result['summary']['total_access_entries']}")
print(f"Dataflows processados: {access_result['summary']['dataflows_processed']}")
```

---

### Estrutura do Output
```python
{
  "dataflow_access": [
    {
      "dataflow_id": "dataflow-123",
      "dataflow_name": "Customer ETL",
      "workspace_id": "abc-123",
      "workspace_name": "Marketing Analytics",
      "user_email": "user@company.com",
      "user_identifier": "user-guid",
      "principal_type": "User",
      "permission": "Owner"  # Owner, User
    }
  ],
  "dataflow_access_errors": [...],
  "summary": {
    "total_dataflows": 6,
    "personal_workspaces_dataflows_skipped": 2,
    "dataflows_processed": 4,
    "dataflows_with_users": 3,
    "total_access_entries": 12,
    "users_count": 5,
    "service_principals_count": 1,
    "permissions_breakdown": {
      "Owner": 8,
      "User": 4
    },
    "errors_count": 0
  }
}
```

---

### Performance

**Tenant de referência (6 dataflows):**
- **Dataflows filtrados:** 4 (2 em Personal Workspaces ignorados)
- **Tempo de execução:** ~2 minutos
- **Acessos coletados:** ~12 entradas
- **Checkpoint interval:** a cada 50 dataflows

**Nota:** Dataflows são menos comuns que reports/datasets, então rate limit raramente é problema.

---

### Limitações e Rate Limiting

#### Rate Limit da API

A API `GET /admin/dataflows/{dataflowId}/users` tem **limite de ~200 requests/hora** (não documentado oficialmente).

**Mesma estratégia dos outros collectors:**
- Ao detectar `429`, salva checkpoint e encerra
- Retoma de onde parou em próxima execução

---

#### Dataflows em Personal Workspaces

**Dataflows em Personal Workspaces não suportam a API de usuários.**

**Comportamento:**
- Retornam `404 Not Found` ou `429 Too Many Requests`
- São **automaticamente filtrados** pelo coletor antes de fazer chamadas

---

### Casos de Uso

#### 1. Dataflows sem owner (órfãos)
```python
from collections import defaultdict

result = access_collector.collect()

dataflow_owners = defaultdict(list)
for access in result['dataflow_access']:
    if access['permission'] == 'Owner':
        dataflow_owners[access['dataflow_id']].append(access['user_email'])

orphaned = [
    df_id for df_id, owners in dataflow_owners.items()
    if len(owners) == 0
]

print(f"⚠️  {len(orphaned)} dataflows sem owner")
```

---

## 📊 Exemplo Completo: Coleta de Inventário + Acessos
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import (
    WorkspaceInventoryCollector,
    WorkspaceAccessCollector,
    ReportAccessCollector,
)
from fabricgov.exporters import FileExporter
from datetime import datetime

# Callback de progresso
log_messages = []

def progress(msg: str):
    timestamp_msg = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(timestamp_msg)
    log_messages.append(timestamp_msg)

# Autenticação
auth = ServicePrincipalAuth.from_env()

# Etapa 1: Inventário
inventory_collector = WorkspaceInventoryCollector(
    auth=auth,
    progress_callback=progress
)
inventory_result = inventory_collector.collect()

# Etapa 2: Acessos de Workspaces
workspace_access_collector = WorkspaceAccessCollector(
    auth=auth,
    inventory_result=inventory_result,
    progress_callback=progress
)
workspace_access_result = workspace_access_collector.collect()

# Etapa 3: Acessos de Reports
report_access_collector = ReportAccessCollector(
    auth=auth,
    inventory_result=inventory_result,
    progress_callback=progress
)
report_access_result = report_access_collector.collect()

# Etapa 4: Exporta tudo
exporter = FileExporter(format="csv", output_dir="output")

exporter.export(inventory_result, log_messages)
exporter.export(workspace_access_result, [])
exporter.export(report_access_result, [])

print("✓ Coleta e export concluídos")
```

---

## 🛠️ BaseCollector — Funcionalidades Comuns

Todos os coletores herdam do `BaseCollector`, que provê:

### Retry Automático

Erros transientes (429, 500, 503) são retentados automaticamente com **exponential backoff**:

- Tentativa 1: delay = 1s
- Tentativa 2: delay = 2s
- Tentativa 3: delay = 4s
```python
collector = WorkspaceInventoryCollector(
    auth=auth,
    max_retries=5,      # Padrão: 3
    retry_delay=2.0     # Padrão: 1.0s
)
```

---

### Rate Limiting

Delay automático entre requests sucessivos para evitar throttling:
```python
collector = WorkspaceInventoryCollector(
    auth=auth,
    request_delay=0.5   # 500ms entre requests (padrão: 0.1s)
)
```

---

### Paginação Automática

O método `_paginate()` do `BaseCollector` lida automaticamente com `continuationToken`:
```python
# Dentro de um coletor customizado
items = self._paginate(
    endpoint="/v1/workspaces",
    scope="https://api.fabric.microsoft.com/.default",
    params={"$top": 5000}
)
```

---

### Timeout Configurável
```python
collector = WorkspaceInventoryCollector(
    auth=auth,
    timeout=60  # 60 segundos (padrão: 30)
)
```

---

## 🚧 Coletores em Desenvolvimento

Os seguintes coletores estão planejados para versões futuras:

- **CapacityConsumptionCollector** — métricas de CU via DAX queries
- **SecurityAccessCollector** — roles e permissões detalhadas em datasets/dashboards
- **RefreshMonitoringCollector** — histórico de refresh e datasources
- **ConnectionsCollector** — conexões e permissões por conexão

Acompanhe o [Roadmap no README](../README.md#-roadmap) para atualizações.

---

**[← Voltar: Autenticação](authentication.md)** | **[Próximo: Exportadores →](exporters.md)**