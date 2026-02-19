# Guia de Exportadores

Os **exportadores** são responsáveis por transformar os resultados dos coletores em arquivos estruturados e organizados. O `FileExporter` é o exportador principal da biblioteca, suportando formatos JSON e CSV.

---

## 📁 FileExporter

### Visão Geral

O `FileExporter` cria uma estrutura de arquivos organizada por timestamp, garantindo que múltiplas execuções não sobrescrevam resultados anteriores.

**Estrutura de output:**
```
output/
├── 20260219_120000/
│   ├── log.txt
│   ├── summary.json
│   ├── workspaces.json (ou .csv)
│   ├── reports.json (ou .csv)
│   ├── datasets.json (ou .csv)
│   └── ...
├── 20260219_150000/
│   └── ...
└── 20260219_180000/
    └── ...
```

---

## 🚀 Uso Básico

### JSON (padrão)
```python
from fabricgov.exporters import FileExporter

exporter = FileExporter(format="json", output_dir="output")
output_path = exporter.export(result, log_messages)

print(f"✓ Arquivos exportados em: {output_path}")
```

### CSV
```python
exporter = FileExporter(format="csv", output_dir="output")
output_path = exporter.export(result, log_messages)
```

---

## 📋 Parâmetros
```python
FileExporter(
    format: Literal["json", "csv"] = "json",
    output_dir: str = "output"
)
```

| Parâmetro | Tipo | Descrição | Padrão |
|-----------|------|-----------|--------|
| `format` | `"json"` ou `"csv"` | Formato de exportação | `"json"` |
| `output_dir` | `str` | Diretório raiz onde criar pastas timestampadas | `"output"` |

---

## 📂 Estrutura de Arquivos

### Arquivos sempre criados

#### `log.txt`
Log completo da execução com:
- Progresso passo a passo (timestamps)
- Resumo consolidado (workspaces, itens, duração)
- Artefatos encontrados (ordenados por contagem)
- Tipos de artefatos não encontrados

**Exemplo:**
```
======================================================================
FABRICGOV - LOG DE EXECUÇÃO
======================================================================

PROGRESSO:
----------------------------------------------------------------------
[16:33:36] Listando workspaces do tenant...
[16:33:36] Encontrados 302 workspaces
[16:33:36] Dividido em 4 lote(s) de até 100 workspaces
...

======================================================================
RESUMO:
======================================================================
Total de workspaces: 302
Total de itens: 1367
Duração: 23.82s
Lotes processados: 4

ARTEFATOS ENCONTRADOS:
----------------------------------------------------------------------
  reports                                777
  datasets                               506
  dashboards                              65
  warehouses                              11
  dataflows                                6
  datamarts                                2

TIPOS DE ARTEFATOS NÃO ENCONTRADOS:
----------------------------------------------------------------------
  deploymentPipelines
  eventstreams
  graphqlApis
  ...
```

---

#### `summary.json`
Sempre em formato JSON, independente do formato escolhido.
```json
{
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
  "batches_processed": 4
}
```

---

### Arquivos condicionais

**Um arquivo por tipo de artefato** (só criado se `count > 0`):

- `workspaces.json` / `workspaces.csv`
- `reports.json` / `reports.csv`
- `datasets.json` / `datasets.csv`
- `dashboards.json` / `dashboards.csv`
- `dataflows.json` / `dataflows.csv`
- `datamarts.json` / `datamarts.csv`
- `lakehouses.json` / `lakehouses.csv`
- `warehouses.json` / `warehouses.csv`
- `notebooks.json` / `notebooks.csv`
- ... (todos os 27+ tipos)
- `datasourceInstances.json` / `datasourceInstances.csv`
- `misconfiguredDatasourceInstances.json` / `.csv`

---

## 📊 Formato JSON

### Características

- ✅ Estrutura hierárquica preservada
- ✅ Arrays e objetos aninhados mantidos
- ✅ Encoding UTF-8 com acentuação correta
- ✅ Pretty-print (indentação de 2 espaços)
- ✅ Fácil de importar em outras ferramentas (Python, Power BI, etc.)

### Exemplo de arquivo

**workspaces.json:**
```json
[
  {
    "id": "abc-123",
    "name": "Marketing Analytics",
    "description": "Workspace for marketing team",
    "type": "Workspace",
    "state": "Active",
    "isOnDedicatedCapacity": true,
    "capacityId": "def-456"
  },
  {
    "id": "xyz-789",
    "name": "Finance Reports",
    ...
  }
]
```

**datasets.json:**
```json
[
  {
    "id": "dataset-123",
    "name": "Sales Data",
    "configuredBy": "user@company.com",
    "isRefreshable": true,
    "workspace_id": "abc-123",
    "workspace_name": "Marketing Analytics",
    ...
  }
]
```

---

## 📈 Formato CSV

### Características

- ✅ Compatível com Excel, Power BI, Pandas
- ✅ Objetos aninhados são **achatados** (ex: `user.name` → `user_name`)
- ✅ Arrays são convertidos em strings JSON
- ✅ Encoding UTF-8
- ✅ Header com nomes de colunas
- ✅ Cada tipo de artefato vira um arquivo CSV separado

### Achatamento de Estruturas

**JSON original:**
```json
{
  "id": "dataset-123",
  "name": "Sales",
  "sensitivityLabel": {
    "labelId": "label-456",
    "labelName": "Confidential"
  },
  "users": [
    {"email": "user@company.com", "role": "Admin"}
  ]
}
```

**CSV achatado:**
```csv
id,name,sensitivityLabel_labelId,sensitivityLabel_labelName,users,workspace_id,workspace_name
dataset-123,Sales,label-456,Confidential,"[{""email"":""user@company.com"",""role"":""Admin""}]",abc-123,Marketing Analytics
```

**Leitura em Pandas:**
```python
import pandas as pd
import json

df = pd.read_csv("datasets.csv")

# Reconstrói array de users
df['users_parsed'] = df['users'].apply(json.loads)
```

---

## 🔄 Uso Avançado

### Exemplo Completo com Log Messages
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exporters import FileExporter
from datetime import datetime

# Captura log messages
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

# Exporta em JSON
exporter_json = FileExporter(format="json", output_dir="output")
json_path = exporter_json.export(result, log_messages)

# Exporta também em CSV (em outra pasta timestampada)
exporter_csv = FileExporter(format="csv", output_dir="output")
csv_path = exporter_csv.export(result, log_messages)

print(f"\n✓ JSON exportado em: {json_path}")
print(f"✓ CSV exportado em: {csv_path}")
```

---

### Customizar Diretório de Output
```python
# Output em pasta personalizada
exporter = FileExporter(
    format="json",
    output_dir="assessments/production"
)
```

**Resultado:**
```
assessments/
└── production/
    └── 20260219_120000/
        └── ...
```

---

### Múltiplas Execuções
```python
import time

for i in range(3):
    result = collector.collect()
    output_path = exporter.export(result, log_messages)
    print(f"Execução {i+1} exportada em: {output_path}")
    time.sleep(2)  # Garante timestamp diferente
```

**Resultado:**
```
output/
├── 20260219_120000/
├── 20260219_120002/
└── 20260219_120004/
```

---

## 📦 Integração com Outras Ferramentas

### Power BI Desktop

**1. Importar CSV:**
- Abra o Power BI Desktop
- Get Data → Text/CSV
- Selecione `workspaces.csv`, `reports.csv`, etc.
- Relacione via `workspace_id`

**2. Importar JSON:**
- Get Data → JSON
- Selecione `workspaces.json`
- Transform Data → Expand columns

---

### Python / Pandas
```python
import pandas as pd
import json
from pathlib import Path

# Lê múltiplos arquivos CSV
output_dir = Path("output/20260219_120000")

workspaces = pd.read_csv(output_dir / "workspaces.csv")
datasets = pd.read_csv(output_dir / "datasets.csv")
reports = pd.read_csv(output_dir / "reports.csv")

# Merge via workspace_id
df = datasets.merge(
    workspaces[['id', 'name', 'capacityId']],
    left_on='workspace_id',
    right_on='id',
    suffixes=('_dataset', '_workspace')
)

print(df.head())
```

**JSON:**
```python
# Lê JSON
with open(output_dir / "datasets.json") as f:
    datasets = json.load(f)

# Converte para DataFrame
df = pd.DataFrame(datasets)
```

---

### Azure Data Lake / Blob Storage
```python
from azure.storage.blob import BlobServiceClient
from pathlib import Path

# Conecta ao storage
blob_service = BlobServiceClient.from_connection_string(conn_str)
container_client = blob_service.get_container_client("governance")

# Faz upload de todos os arquivos
output_dir = Path("output/20260219_120000")
for file_path in output_dir.glob("*"):
    blob_client = container_client.get_blob_client(file_path.name)
    with open(file_path, "rb") as data:
        blob_client.upload_blob(data, overwrite=True)

print(f"✓ {len(list(output_dir.glob('*')))} arquivos enviados para o Azure")
```

---

### Banco de Dados SQL
```python
import sqlite3
import pandas as pd
from pathlib import Path

# Conecta ao banco
conn = sqlite3.connect("governance.db")

# Lê CSVs e insere no banco
output_dir = Path("output/20260219_120000")

workspaces = pd.read_csv(output_dir / "workspaces.csv")
workspaces.to_sql("workspaces", conn, if_exists="replace", index=False)

datasets = pd.read_csv(output_dir / "datasets.csv")
datasets.to_sql("datasets", conn, if_exists="replace", index=False)

reports = pd.read_csv(output_dir / "reports.csv")
reports.to_sql("reports", conn, if_exists="replace", index=False)

conn.close()
print("✓ Dados inseridos no banco SQLite")
```

---

## 🔍 Análise de Outputs

### Comparar Execuções
```python
import json
from pathlib import Path

# Lê summaries de duas execuções
run1 = json.load(open("output/20260219_120000/summary.json"))
run2 = json.load(open("output/20260219_150000/summary.json"))

# Compara totais
print(f"Workspaces: {run1['total_workspaces']} → {run2['total_workspaces']}")
print(f"Itens: {run1['total_items']} → {run2['total_items']}")

# Delta por tipo
for artifact_type in run1['items_by_type']:
    count1 = run1['items_by_type'].get(artifact_type, 0)
    count2 = run2['items_by_type'].get(artifact_type, 0)
    delta = count2 - count1
    if delta != 0:
        print(f"{artifact_type}: {count1} → {count2} ({delta:+d})")
```

---

### Encontrar Outputs Mais Recentes
```python
from pathlib import Path

output_dir = Path("output")
runs = sorted(output_dir.glob("*/"), reverse=True)

if runs:
    latest = runs[0]
    print(f"Última execução: {latest.name}")
    print(f"Arquivos: {list(latest.glob('*.json'))}")
```

---

## ⚙️ Configurações Recomendadas

### Para Análise no Power BI
```python
exporter = FileExporter(
    format="csv",  # CSV é mais natural no Power BI
    output_dir="output"
)
```

### Para Backup / Arquivamento
```python
exporter = FileExporter(
    format="json",  # JSON preserva estrutura completa
    output_dir="archives"
)
```

### Para Processamento em Python
```python
exporter = FileExporter(
    format="json",  # Pandas lê JSON nativamente
    output_dir="data"
)
```

---

## 🚧 Limitações Conhecidas

1. **CSV com arrays aninhados:** Arrays são convertidos em strings JSON — requer parsing manual
2. **Nomes de colunas longos:** Objetos profundamente aninhados geram nomes como `extendedProperties_DwProperties_endpoint`
3. **Tamanho de arquivos:** Tenants grandes (1000+ workspaces) podem gerar arquivos de 50-100MB

---

## 📚 Recursos Adicionais

- [Pandas Documentation](https://pandas.pydata.org/docs/)
- [Power BI CSV Import](https://learn.microsoft.com/power-bi/connect-data/desktop-connect-csv)
- [Azure Blob Storage Python SDK](https://learn.microsoft.com/azure/storage/blobs/storage-quickstart-blobs-python)

---

**[← Voltar: Coletores](collectors.md)** | **[Próximo: Contribuindo →](contributing.md)**