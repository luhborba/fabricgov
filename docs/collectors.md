# Guia de Coletores

Os **coletores** são responsáveis por buscar dados específicos das APIs do Microsoft Fabric e Power BI. Cada coletor herda comportamentos comuns do `BaseCollector` (retry, paginação, rate limiting) e implementa lógica específica para seu domínio.

---

## 📦 Coletores Disponíveis (10 ativos + 3 deprecated)

### Inventário & Acesso
| Coletor | CLI | Checkpoint | Obs |
|---------|-----|------------|-----|
| `WorkspaceInventoryCollector` | `collect inventory` | ✅ | Inclui `artifact_users`, `datasources` e `semantic_models` (v1.1.0) |
| `WorkspaceAccessCollector` | `collect workspace-access` | — | |
| ~~`ReportAccessCollector`~~ | ~~`collect report-access`~~ | — | **Deprecated v1.1.0** — use `inventory` |
| ~~`DatasetAccessCollector`~~ | ~~`collect dataset-access`~~ | — | **Deprecated v1.1.0** — use `inventory` |
| ~~`DataflowAccessCollector`~~ | ~~`collect dataflow-access`~~ | — | **Deprecated v1.1.0** — use `inventory` |

### Refresh
| Coletor | CLI | Checkpoint |
|---------|-----|------------|
| `RefreshHistoryCollector` | `collect refresh-history` | ✅ |
| `RefreshScheduleCollector` | `collect refresh-schedules` | — |

### Infraestrutura
| Coletor | CLI | Checkpoint |
|---------|-----|------------|
| `DomainCollector` | `collect domains` | — |
| `TagCollector` | `collect tags` | — |
| `CapacityCollector` | `collect capacities` | — |
| `WorkloadCollector` | `collect workloads` | — |

### Atividades (v0.9.0)
| Coletor | CLI | Checkpoint |
|---------|-----|------------|
| `ActivityCollector` | `collect activity --days N` | — |

> 📘 [Guia completo do ActivityCollector →](activity.md)

---

## 🔍 WorkspaceInventoryCollector

### O que coleta

- **Workspaces:** metadados de todos os workspaces do tenant (PersonalGroup excluídos automaticamente desde v1.1.0)
- **27+ tipos de artefatos** (Lakehouse, Notebook, Report, Dataset, DataPipeline, etc.)
- **Datasources:** `datasourceInstances` e `misconfiguredDatasourceInstances`
- **Usuários por artefato** *(v1.1.0)* — `artifact_users`: lista plana com `accessRight` normalizado para todos os 22 tipos de artefato que suportam usuários
- **Datasources por dataset** *(v1.1.0)* — `datasources`: tipo, detalhes de conexão, gateway
- **Modelos semânticos** *(v1.1.0)* — `semantic_models`: tabelas, colunas, medidas, relacionamentos e expressões DAX/M por dataset

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

### Estrutura do Output
```python
{
  "workspaces": [
    {
      "id": "workspace-guid",
      "name": "workspace-name",
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
      "refreshSchedule": { ... },  # se configurado
      ...
    }
  ],
  "reports": [...],
  "dashboards": [...],
  // ... outros tipos de artefatos
  "datasourceInstances": [...],
  "misconfiguredDatasourceInstances": [...],
  "artifact_users": [
    {
      "artifact_type": "reports",
      "artifact_id": "report-guid",
      "artifact_name": "Sales Dashboard",
      "workspace_id": "workspace-guid",
      "workspace_name": "Marketing Analytics",
      "emailAddress": "user@company.com",
      "displayName": "User Name",
      "principalType": "User",
      "accessRight": "Owner"
    }
  ],
  "datasources": [
    {
      "workspace_id": "workspace-guid",
      "dataset_id": "dataset-guid",
      "dataset_name": "Sales Data",
      "datasource_type": "Sql",
      "connection_details": "{'server': 'srv', 'database': 'db'}",
      "datasource_id": "datasource-guid",
      "gateway_id": "gateway-guid"
    }
  ],
  "semantic_models": [
    {
      "workspace_id": "workspace-guid",
      "dataset_id": "dataset-guid",
      "dataset_name": "Sales Data",
      "tables": [
        {
          "name": "Vendas",
          "columns": [{"name": "id"}, {"name": "valor"}],
          "measures": [{"name": "Total Vendas"}],
          "isHidden": false
        }
      ],
      "relationships": [...],
      "expressions": [...]
    }
  ],
  "summary": {
    "total_workspaces": 302,
    "total_items": 1367,
    "items_by_type": {
      "reports": 777,
      "datasets": 506,
      "dashboards": 65,
      "warehouses": 11,
      "dataflows": 6,
      "datamarts": 2
    },
    "scan_duration_seconds": 23.82,
    "batches_processed": 4,
    "total_artifact_users": 5200,
    "total_datasources": 480,
    "total_semantic_models": 506
  }
}
```

> **Nota v1.1.0:** `artifact_users`, `datasources` e `semantic_models` são extraídos diretamente do resultado da Scanner API — **sem chamadas extras**. O `inventory_result` continua sendo o pré-requisito para `WorkspaceAccessCollector` e collectors de Refresh.

---

### Performance

**Tenant de referência (302 workspaces):**
- **Tempo de execução:** ~24 segundos
- **Lotes processados:** 4 (100 + 100 + 100 + 2)
- **Itens coletados:** 1367 artefatos

---

### Casos de Uso

#### Identificar workspaces órfãos
```python
result = collector.collect()

orphaned = [ws for ws in result['workspaces'] if ws.get('isOrphaned') == True]
print(f"Workspaces órfãos: {len(orphaned)}")
```

#### Detectar datasources com erro de configuração
```python
misconfigured = result['misconfiguredDatasourceInstances']
if misconfigured:
    print(f"⚠️  {len(misconfigured)} datasources com erro de configuração")
```

#### Listar usuários com acesso a Lakehouses
```python
lakehouse_users = [
    u for u in result['artifact_users']
    if u['artifact_type'] == 'Lakehouse'
]
print(f"Usuários com acesso a Lakehouses: {len(lakehouse_users)}")
```

#### Ver datasources utilizados nos datasets
```python
import pandas as pd

df = pd.DataFrame(result['datasources'])
print(df.groupby('datasource_type').size().sort_values(ascending=False))
```

#### Inspecionar modelos semânticos (tabelas e medidas)
```python
for model in result['semantic_models']:
    if model['tables']:
        table_names = [t['name'] for t in model['tables']]
        print(f"{model['dataset_name']}: {table_names}")
```

---

## 🔐 WorkspaceAccessCollector

Extrai roles de acesso (Admin, Member, Contributor, Viewer) em workspaces via Power BI Admin API.

### O que coleta

- **Roles em workspaces:** Admin, Member, Contributor, Viewer
- **Usuários e Service Principals** com acesso

**Filtragem automática:** Personal Workspaces são ignorados (não suportam API de usuários).

---

### Parâmetros do Construtor
```python
WorkspaceAccessCollector(
    auth: AuthProvider,
    inventory_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    progress_manager: ProgressManager | None = None,
    **kwargs
)
```

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `auth` | `AuthProvider` | ServicePrincipalAuth ou DeviceFlowAuth |
| `inventory_result` | `dict` | Resultado do WorkspaceInventoryCollector.collect() |
| `progress_callback` | `Callable` | Função chamada a cada update de progresso |
| `progress_manager` | `ProgressManager` | Progress bar rich (usado internamente pelo `collect all`) |

---

### Uso Básico
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector, WorkspaceAccessCollector

auth = ServicePrincipalAuth.from_env()

inventory_result = WorkspaceInventoryCollector(auth=auth).collect()

access_collector = WorkspaceAccessCollector(
    auth=auth,
    inventory_result=inventory_result
)
result = access_collector.collect()

print(f"Total de acessos: {result['summary']['total_access_entries']}")
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
      "principal_type": "User",  # ou "App"
      "role": "Admin"  # Admin, Member, Contributor, Viewer
    }
  ],
  "workspace_access_errors": [...],
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

### Casos de Uso

#### Auditoria de acessos privilegiados
```python
result = access_collector.collect()

admins = [a for a in result['workspace_access'] if a['role'] == 'Admin']
print(f"Total de Admins: {len(admins)}")
```

#### Workspaces com apenas 1 Admin (risco de órfão)
```python
from collections import defaultdict

workspaces_admins = defaultdict(list)
for a in result['workspace_access']:
    if a['role'] == 'Admin':
        workspaces_admins[a['workspace_id']].append(a['user_email'])

at_risk = {ws: admins for ws, admins in workspaces_admins.items() if len(admins) == 1}
print(f"⚠️  {len(at_risk)} workspaces com apenas 1 Admin")
```

---

## 📄 ReportAccessCollector *(Deprecated)*

> **⚠️ Deprecated desde v1.1.0.** Use `WorkspaceInventoryCollector` — os dados de acesso por artefato estão disponíveis na chave `artifact_users` do resultado do `inventory`, obtidos em uma única chamada à Scanner API sem risco de rate limit por artefato.

Extrai permissões de acesso em reports via Power BI Admin API (uma chamada por report).

### O que coleta

- **Permissões em reports:** Owner, Read, ReadWrite, ReadCopy, ReadReshare, ReadExplore
- Suporte a checkpoint para tenants grandes

---

### Parâmetros do Construtor
```python
ReportAccessCollector(
    auth: AuthProvider,
    inventory_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    checkpoint_file: str | Path | None = None,
    progress_manager: ProgressManager | None = None,
    **kwargs
)
```

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `auth` | `AuthProvider` | ServicePrincipalAuth ou DeviceFlowAuth |
| `inventory_result` | `dict` | Resultado do WorkspaceInventoryCollector |
| `progress_callback` | `Callable` | Função chamada a cada update de progresso |
| `checkpoint_file` | `str\|Path` | Caminho do checkpoint (habilita modo incremental) |
| `progress_manager` | `ProgressManager` | Progress bar rich (usado internamente pelo `collect all`) |

---

### Uso Básico
```python
from fabricgov.collectors import ReportAccessCollector
from fabricgov.exceptions import CheckpointSavedException

collector = ReportAccessCollector(
    auth=auth,
    inventory_result=inventory_result,
    checkpoint_file="output/checkpoint_report_access.json"
)

try:
    result = collector.collect()
except CheckpointSavedException as e:
    print(f"⏹️  {e.progress} — Execute novamente após 1h30min")
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
      "ReadCopy": 164,
      "Read": 230,
      "ReadReshare": 15,
      "ReadWrite": 7
    },
    "errors_count": 3
  }
}
```

---

### Casos de Uso

#### Reports compartilhados externamente
```python
external_shares = [
    a for a in result['report_access']
    if not a['user_email'].endswith('@yourcompany.com')
]
print(f"Reports compartilhados externamente: {len(external_shares)}")
```

---

## 📊 DatasetAccessCollector *(Deprecated)*

> **⚠️ Deprecated desde v1.1.0.** Use `WorkspaceInventoryCollector` — os dados de acesso por artefato estão disponíveis na chave `artifact_users` do resultado do `inventory`.

### O que coleta

- **Permissões em datasets:** Read, ReadWrite, Build, Reshare
- Checkpoint automático a cada 100 datasets

---

### Parâmetros do Construtor
```python
DatasetAccessCollector(
    auth: AuthProvider,
    inventory_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    checkpoint_file: str | Path | None = None,
    progress_manager: ProgressManager | None = None,
    **kwargs
)
```

---

### Uso Básico
```python
from fabricgov.collectors import DatasetAccessCollector
from fabricgov.exceptions import CheckpointSavedException

collector = DatasetAccessCollector(
    auth=auth,
    inventory_result=inventory_result,
    checkpoint_file="output/checkpoint_dataset_access.json"
)

try:
    result = collector.collect()
except CheckpointSavedException as e:
    print(f"⏹️  {e.progress} — Execute novamente após 1h30min")
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

### Casos de Uso

#### Datasets com permissão Build (alto privilégio)
```python
build_permissions = [
    a for a in result['dataset_access']
    if a['permission'] == 'Build'
]
print(f"⚠️  {len(build_permissions)} usuários com permissão Build")
```

---

## 🌊 DataflowAccessCollector *(Deprecated)*

> **⚠️ Deprecated desde v1.1.0.** Use `WorkspaceInventoryCollector` — os dados de acesso por artefato estão disponíveis na chave `artifact_users` do resultado do `inventory`.

### O que coleta

- **Permissões em dataflows:** Owner, User
- Checkpoint automático a cada 50 dataflows

---

### Parâmetros do Construtor
```python
DataflowAccessCollector(
    auth: AuthProvider,
    inventory_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    checkpoint_file: str | Path | None = None,
    progress_manager: ProgressManager | None = None,
    **kwargs
)
```

---

### Uso Básico
```python
from fabricgov.collectors import DataflowAccessCollector
from fabricgov.exceptions import CheckpointSavedException

collector = DataflowAccessCollector(
    auth=auth,
    inventory_result=inventory_result,
    checkpoint_file="output/checkpoint_dataflow_access.json"
)

try:
    result = collector.collect()
except CheckpointSavedException as e:
    print(f"⏹️  {e.progress} — Execute novamente após 1h30min")
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
    "permissions_breakdown": { "Owner": 8, "User": 4 },
    "errors_count": 0
  }
}
```

---

## 🔄 RefreshHistoryCollector

Coleta histórico de refreshes de datasets e dataflows via Power BI Admin API.

### O que coleta

- **Datasets:** via `GET /v1.0/myorg/admin/datasets/{datasetId}/refreshes`
- **Dataflows:** via `GET /v1.0/myorg/admin/dataflows/{dataflowId}/transactions`
- Para cada refresh: tipo, status, horários de início/fim, **duração calculada**, detalhes de erro

**Filtragem automática:** Personal Workspaces são ignorados.

---

### Parâmetros do Construtor
```python
RefreshHistoryCollector(
    auth: AuthProvider,
    inventory_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    checkpoint_file: str | Path | None = None,
    history_limit: int = 100,
    progress_manager: ProgressManager | None = None,
    **kwargs
)
```

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `auth` | `AuthProvider` | ServicePrincipalAuth ou DeviceFlowAuth |
| `inventory_result` | `dict` | Resultado do WorkspaceInventoryCollector |
| `progress_callback` | `Callable` | Função chamada a cada update de progresso |
| `checkpoint_file` | `str\|Path` | Caminho do checkpoint (habilita modo incremental) |
| `history_limit` | `int` | Máximo de refreshes a coletar por artefato (padrão: 100) |
| `progress_manager` | `ProgressManager` | Progress bar rich (usado internamente pelo `collect all`) |

---

### Uso Básico
```python
from fabricgov.collectors import RefreshHistoryCollector
from fabricgov.exceptions import CheckpointSavedException

collector = RefreshHistoryCollector(
    auth=auth,
    inventory_result=inventory_result,
    checkpoint_file="output/checkpoint_refresh_history.json",
    history_limit=50
)

try:
    result = collector.collect()
except CheckpointSavedException as e:
    print(f"⏹️  {e.progress} — Execute novamente após 1h30min")
```

---

### Estrutura do Output
```python
{
  "refresh_history": [
    {
      "artifact_type": "Dataset",          # "Dataset" ou "Dataflow"
      "artifact_id": "dataset-123",
      "artifact_name": "Sales Data",
      "workspace_id": "abc-123",
      "workspace_name": "Marketing Analytics",
      "refresh_type": "Scheduled",         # Scheduled, OnDemand, ViaApi, etc.
      "start_time": "2026-02-20T01:00:00Z",
      "end_time": "2026-02-20T01:03:24Z",
      "status": "Completed",               # Completed, Failed, Cancelled, Unknown
      "duration_seconds": 204,             # calculado automaticamente
      "request_id": "request-guid",
      "service_exception_json": null       # detalhes do erro, se houver
    }
  ],
  "refresh_history_errors": [...],
  "summary": {
    "total_artifacts": 532,
    "artifacts_processed": 532,
    "total_refreshes": 18420,
    "refreshes_by_artifact_type": { "Dataset": 17800, "Dataflow": 620 },
    "refreshes_by_status": {
      "Completed": 16800,
      "Failed": 1200,
      "Cancelled": 420
    },
    "total_duration_seconds": 4820400,
    "errors_count": 12
  }
}
```

---

### Limitações Conhecidas

- **API retorna máximo de 3 dias** de histórico para datasets (limitação Microsoft)
- Datasets sem refresh recente retornam **404** — registrados como erro, comportamento normal
- Em tenants com muitos datasets antigos, taxa de 404 pode ser alta (~77%)

---

### Casos de Uso

#### Identificar datasets com falhas recorrentes
```python
from collections import defaultdict

failed_by_dataset = defaultdict(int)
for refresh in result['refresh_history']:
    if refresh['status'] == 'Failed':
        failed_by_dataset[refresh['artifact_name']] += 1

top_failures = sorted(failed_by_dataset.items(), key=lambda x: -x[1])[:10]
for name, count in top_failures:
    print(f"  {name}: {count} falhas")
```

---

## 📅 RefreshScheduleCollector

Extrai configurações de agendamento de refreshes do inventory result.

### O que coleta

- **Agendamentos de datasets e dataflows** com schedule configurado
- Dias da semana, horários, fuso horário, configuração de notificações
- **Não faz chamadas à API** — lê dados já presentes no `inventory_result`

---

### Parâmetros do Construtor
```python
RefreshScheduleCollector(
    auth: AuthProvider,        # Não usado, mas necessário por herança
    inventory_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    **kwargs
)
```

---

### Uso Básico
```python
from fabricgov.collectors import RefreshScheduleCollector

collector = RefreshScheduleCollector(
    auth=auth,
    inventory_result=inventory_result
)
result = collector.collect()

print(f"Schedules encontrados: {result['summary']['total_schedules_found']}")
print(f"Habilitados: {result['summary']['schedules_enabled']}")
```

---

### Estrutura do Output
```python
{
  "refresh_schedules": [
    {
      "artifact_type": "Dataset",
      "artifact_id": "dataset-123",
      "artifact_name": "Sales Data",
      "workspace_id": "abc-123",
      "workspace_name": "Marketing Analytics",
      "enabled": true,
      "days": "Sunday,Monday,Tuesday,Wednesday,Thursday,Friday,Saturday",
      "times": "00:00,08:00,16:00",
      "timezone": "E. South America Standard Time",
      "notify_option": "MailOnFailure"    # MailOnFailure, NoNotification, Always
    }
  ],
  "summary": {
    "total_artifacts_scanned": 532,
    "total_datasets": 506,
    "total_dataflows": 26,
    "total_schedules_found": 312,
    "schedules_enabled": 287,
    "schedules_disabled": 25,
    "schedules_by_artifact_type": { "Dataset": 295, "Dataflow": 17 }
  }
}
```

---

## 🏢 DomainCollector

Coleta todos os domínios do tenant via Fabric Admin API.

### O que coleta

- **Domínios:** id, nome, descrição, hierarquia (pai/filho), sensitivity label padrão
- API: `GET https://api.fabric.microsoft.com/v1/admin/domains`

---

### Parâmetros do Construtor
```python
DomainCollector(
    auth: AuthProvider,
    progress_callback: Callable[[str], None] | None = None,
    non_empty_only: bool = False,
    **kwargs
)
```

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `auth` | `AuthProvider` | ServicePrincipalAuth ou DeviceFlowAuth |
| `progress_callback` | `Callable` | Função chamada a cada update de progresso |
| `non_empty_only` | `bool` | Se `True`, retorna apenas domínios com workspaces ativos (padrão: `False`) |

---

### Uso Básico
```python
from fabricgov.collectors import DomainCollector

collector = DomainCollector(auth=auth)
result = collector.collect()

print(f"Total de domínios: {result['summary']['total_domains']}")
print(f"  Raiz: {result['summary']['root_domains']}")
print(f"  Sub-domínios: {result['summary']['sub_domains']}")
```

---

### Estrutura do Output
```python
{
  "domains": [
    {
      "id": "domain-guid",
      "displayName": "Data Engineering",
      "description": "Domínio para engenharia de dados",
      "parentDomainId": null,         # null = domínio raiz
      "defaultLabelId": "label-guid"  # sensitivity label padrão (opcional)
    },
    {
      "id": "subdomain-guid",
      "displayName": "Lakehouse",
      "parentDomainId": "domain-guid",
      "defaultLabelId": null
    }
  ],
  "summary": {
    "total_domains": 8,
    "root_domains": 3,
    "sub_domains": 5,
    "domains_with_default_label": 2
  }
}
```

---

## 🏷️ TagCollector

Coleta todas as tags do tenant via Fabric Admin API.

### O que coleta

- **Tags:** id, nome, escopo (tenant ou domínio específico)
- API: `GET https://api.fabric.microsoft.com/v1/admin/tags` com paginação automática

---

### Parâmetros do Construtor
```python
TagCollector(
    auth: AuthProvider,
    progress_callback: Callable[[str], None] | None = None,
    **kwargs
)
```

---

### Uso Básico
```python
from fabricgov.collectors import TagCollector

collector = TagCollector(auth=auth)
result = collector.collect()

print(f"Total de tags: {result['summary']['total_tags']}")
print(f"  Tags de tenant: {result['summary']['tenant_tags']}")
print(f"  Tags de domínio: {result['summary']['domain_tags']}")
```

---

### Estrutura do Output
```python
{
  "tags": [
    {
      "id": "tag-guid",
      "displayName": "Produção",
      "scope_type": "Tenant",        # "Tenant" ou "Domain"
      "scope_domain_id": null
    },
    {
      "id": "tag-guid-2",
      "displayName": "Lakehouse",
      "scope_type": "Domain",
      "scope_domain_id": "domain-guid"
    }
  ],
  "summary": {
    "total_tags": 15,
    "tenant_tags": 10,
    "domain_tags": 5
  }
}
```

---

## ⚡ CapacityCollector

Coleta todas as capacidades Premium/Fabric do tenant via Power BI Admin API.

### O que coleta

- **Capacidades:** id, nome, SKU, estado, região, admins, chave de criptografia
- API: `GET /v1.0/myorg/admin/capacities` com paginação

---

### Parâmetros do Construtor
```python
CapacityCollector(
    auth: AuthProvider,
    progress_callback: Callable[[str], None] | None = None,
    **kwargs
)
```

---

### Uso Básico
```python
from fabricgov.collectors import CapacityCollector

collector = CapacityCollector(auth=auth)
result = collector.collect()

print(f"Capacidades: {result['summary']['total_capacities']}")
print(f"  Ativas: {result['summary']['active']}")
print(f"  SKUs: {result['summary']['skus']}")
```

---

### Estrutura do Output
```python
{
  "capacities": [
    {
      "id": "capacity-guid",
      "displayName": "Fabric Production",
      "sku": "F64",
      "state": "Active",              # Active, Suspended, Deleted
      "region": "Brazil South",
      "admins": ["admin@company.com"],
      "capacityUserAccessRight": "Admin",
      "tenantKeyId": null
    }
  ],
  "summary": {
    "total_capacities": 3,
    "active": 2,
    "suspended": 1,
    "skus": { "F64": 1, "P1": 1, "A1": 1 },
    "regions": { "Brazil South": 2, "East US": 1 }
  }
}
```

---

## ⚙️ WorkloadCollector

Coleta workloads configurados em capacidades Gen1 via Power BI API.

### O que coleta

- **Workloads por capacidade:** Dataflows, PaginatedReports, ArtificialIntelligence, etc.
- Estado (Enabled, Disabled, Unsupported) e % de memória configurada
- **Apenas capacidades Gen1** (P-SKU, A-SKU) — capacidades Fabric F-SKU são ignoradas automaticamente

**Pré-requisito:** requer resultado do `CapacityCollector`.

---

### Parâmetros do Construtor
```python
WorkloadCollector(
    auth: AuthProvider,
    capacities_result: dict[str, Any],
    progress_callback: Callable[[str], None] | None = None,
    **kwargs
)
```

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `auth` | `AuthProvider` | ServicePrincipalAuth ou DeviceFlowAuth |
| `capacities_result` | `dict` | Resultado do CapacityCollector.collect() |
| `progress_callback` | `Callable` | Função chamada a cada update de progresso |

---

### Uso Básico
```python
from fabricgov.collectors import CapacityCollector, WorkloadCollector

# Passo 1: coleta capacidades
capacities_result = CapacityCollector(auth=auth).collect()

# Passo 2: coleta workloads (apenas Gen1)
collector = WorkloadCollector(
    auth=auth,
    capacities_result=capacities_result
)
result = collector.collect()

print(f"Workloads coletados: {result['summary']['total_workloads']}")
print(f"Capacidades Gen2 ignoradas: {result['summary']['capacities_skipped_gen2']}")
```

---

### Estrutura do Output
```python
{
  "workloads": [
    {
      "capacity_id": "capacity-guid",
      "capacity_name": "Premium P1",
      "capacity_sku": "P1",
      "workload_name": "Dataflows",
      "state": "Enabled",             # Enabled, Disabled, Unsupported
      "max_memory_percentage": 20     # null se não configurado
    }
  ],
  "workloads_errors": [...],
  "summary": {
    "total_capacities": 3,
    "capacities_processed": 2,
    "capacities_skipped_gen2": 1,
    "total_workloads": 8,
    "enabled": 5,
    "disabled": 2,
    "unsupported": 1,
    "workload_types": {
      "Dataflows": 2,
      "PaginatedReports": 2,
      "ArtificialIntelligence": 2,
      "QueryScale-Out": 2
    },
    "errors": 1
  }
}
```

---

## 🖥️ CLI: Orquestradores

### `fabricgov collect all`

Executa toda a coleta em uma única sessão (pasta de output compartilhada):

```
inventory → all-infrastructure → all-access → all-refresh
```

**Opções:**
- `--format csv|json` — formato de saída (padrão: csv)
- `--output DIR` — pasta raiz (padrão: output)
- `--resume/--no-resume` — retoma sessão anterior (padrão: resume habilitado)
- `--limit N` — máximo de refreshes por artefato (padrão: 100)
- `--progress/--no-progress` — exibe progress bars (padrão: ativo)

```bash
# Coleta completa
fabricgov collect all

# Retomando após rate limit
fabricgov collect all --resume

# Sem progress bars (útil para CI/CD ou log files)
fabricgov collect all --no-progress
```

---

### `fabricgov collect status`

Exibe o status da sessão atual e checkpoints detectados:

```bash
fabricgov collect status
```

**Output:**
```
═══════════════════════════════════════════════════════════════════
STATUS DA SESSÃO
═══════════════════════════════════════════════════════════════════
Pasta:      output/20260226_140001/
Iniciada:   2026-02-26 14:00:01
Status:     INTERROMPIDA

Passos:
  ✅ inventory            concluído 14:00:45
  ✅ all-infrastructure   concluído 14:01:12
  ⏹️  all-access          interrompido 14:32:18
  ⏳ all-refresh          pendente

Checkpoints detectados:
  💾 checkpoint_dataset_access.json

Para retomar: fabricgov collect all --resume
═══════════════════════════════════════════════════════════════════
```

---

## 🛠️ BaseCollector — Funcionalidades Comuns

Todos os coletores herdam do `BaseCollector`, que provê:

### Retry Automático

Erros transientes (429, 500, 503) são retentados com **exponential backoff**:
```python
collector = WorkspaceInventoryCollector(
    auth=auth,
    max_retries=5,      # Padrão: 3
    retry_delay=2.0     # Padrão: 1.0s
)
```

---

### Rate Limiting

Delay automático entre requests:
```python
collector = WorkspaceInventoryCollector(
    auth=auth,
    request_delay=0.5   # 500ms entre requests (padrão: 0.1s)
)
```

---

### Paginação Automática

O método `_paginate()` lida automaticamente com `continuationToken`:
```python
# Dentro de um coletor customizado
items = self._paginate(
    endpoint="/v1/workspaces",
    scope="https://api.fabric.microsoft.com/.default",
    params={"$top": 5000}
)
```

---

**[← Voltar: Autenticação](authentication.md)** | **[Atividades →](activity.md)** | **[Próximo: Exportadores →](exporters.md)**
