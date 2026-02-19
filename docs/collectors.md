# Guia de Coletores

Os **coletores** são responsáveis por buscar dados específicos das APIs do Microsoft Fabric e Power BI. Cada coletor herda comportamentos comuns do `BaseCollector` (retry, paginação, rate limiting) e implementa lógica específica para seu domínio.

---

## 📦 Coletores Disponíveis

### ✅ WorkspaceInventoryCollector

Coleta inventário completo de workspaces e artefatos via **Admin Scan API**.

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

## 📊 Exemplo Completo com Análise
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exporters import FileExporter
from datetime import datetime

# Setup
log_messages = []

def progress(msg: str):
    timestamp_msg = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(timestamp_msg)
    log_messages.append(timestamp_msg)

# Coleta
auth = ServicePrincipalAuth.from_env()
collector = WorkspaceInventoryCollector(
    auth=auth,
    progress_callback=progress
)
result = collector.collect()

# Análise
print("\n" + "="*70)
print("ANÁLISE DO INVENTÁRIO")
print("="*70)

# Workspaces por tipo
workspace_types = {}
for ws in result['workspaces']:
    ws_type = ws.get('type', 'Unknown')
    workspace_types[ws_type] = workspace_types.get(ws_type, 0) + 1

print("\nWorkspaces por tipo:")
for ws_type, count in workspace_types.items():
    print(f"  {ws_type}: {count}")

# Top 10 workspaces com mais artefatos
workspace_item_counts = {}
for item_type in ['datasets', 'reports', 'dashboards']:
    for item in result[item_type]:
        ws_id = item['workspace_id']
        workspace_item_counts[ws_id] = workspace_item_counts.get(ws_id, 0) + 1

top_workspaces = sorted(
    workspace_item_counts.items(),
    key=lambda x: x[1],
    reverse=True
)[:10]

print("\nTop 10 workspaces com mais artefatos:")
for ws_id, count in top_workspaces:
    ws_name = next(
        (ws['name'] for ws in result['workspaces'] if ws['id'] == ws_id),
        "Unknown"
    )
    print(f"  {ws_name}: {count} itens")

# Exporta
exporter = FileExporter(format="csv", output_dir="output")
output_path = exporter.export(result, log_messages)

print(f"\n✓ Arquivos exportados em: {output_path}")
```

---

## 🚧 Coletores em Desenvolvimento

Os seguintes coletores estão planejados para versões futuras:

- **CapacityConsumptionCollector** — métricas de CU via DAX queries
- **SecurityAccessCollector** — roles e permissões detalhadas
- **RefreshMonitoringCollector** — histórico de refresh e datasources
- **ConnectionsCollector** — conexões e permissões por conexão

Acompanhe o [Roadmap no README](../README.md#-roadmap) para atualizações.

---

**[← Voltar: Autenticação](authentication.md)** | **[Próximo: Exportadores →](exporters.md)**