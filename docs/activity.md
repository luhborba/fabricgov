# Coletor de Atividades — Activity Events

Coleta o log de atividades do tenant via Power BI Admin API e exporta para CSV/JSON.

> Guia completo de autenticação: [authentication.md](authentication.md)

---

## O que é coletado?

Cada evento representa uma ação de um usuário no Power BI / Fabric:

| Campo | Descrição |
|-------|-----------|
| `CreationTime` | Data/hora UTC do evento |
| `UserId` | E-mail do usuário |
| `Activity` | Tipo de atividade (ex: `ViewReport`, `ExportArtifact`) |
| `Operation` | Operação realizada |
| `ItemName` | Nome do artefato acessado |
| `ItemType` | Tipo de artefato (`Report`, `Dashboard`, `Dataset`, etc.) |
| `WorkSpaceName` | Nome do workspace |
| `WorkspaceId` | UUID do workspace |
| `DatasetId` | UUID do dataset (quando aplicável) |
| `ReportId` | UUID do report (quando aplicável) |
| `IsSuccess` | Sucesso ou falha da operação |
| `ClientIP` | IP do cliente |
| `UserAgent` | Browser/cliente utilizado |

---

## Limitações da API

| Limitação | Detalhe |
|-----------|---------|
| **Histórico máximo** | **28 dias** para trás |
| **Janela por request** | `startDateTime` e `endDateTime` devem ser **no mesmo dia UTC** |
| **Rate limit** | **200 req/hora** (compartilhado com todas as Admin APIs) |
| **Paginação** | Obrigatória via `continuationToken` |
| **`$filter`** | Apenas `Activity eq '...'`, `UserId eq '...'`, e `and`. Sem `or` ou `contains` |
| **Permissão** | Usuário/SP deve ser **Fabric Administrator** |

---

## Uso básico

```bash
# Últimos 7 dias (padrão)
fabricgov collect activity

# Máximo histórico disponível
fabricgov collect activity --days 28

# Últimos 3 dias, apenas ViewReport
fabricgov collect activity --days 3 --filter-activity ViewReport

# Apenas ações de um usuário específico
fabricgov collect activity --days 7 --filter-user usuario@empresa.com

# Combinar filtros
fabricgov collect activity --days 1 \
  --filter-activity ExportArtifact \
  --filter-user usuario@empresa.com
```

---

## Opções disponíveis

| Opção | Padrão | Descrição |
|-------|--------|-----------|
| `--days N` | `7` | Número de dias de histórico (máximo 28) |
| `--filter-activity NOME` | — | Filtrar por tipo de atividade |
| `--filter-user EMAIL` | — | Filtrar por e-mail do usuário |
| `--format json\|csv` | `csv` | Formato de export |
| `--output DIR` | `output` | Diretório de saída |

---

## Atividades mais comuns

| Activity | Descrição |
|----------|-----------|
| `ViewReport` | Usuário visualizou um report |
| `ViewDashboard` | Usuário visualizou um dashboard |
| `ExportArtifact` | Exportação de dados |
| `ExportReport` | Export para PDF/PPTX |
| `ShareReport` | Compartilhamento de report |
| `DeleteReport` | Deleção de report |
| `CreateReport` | Criação de report |
| `PublishToWebReport` | Publicação para web pública |
| `ViewDataset` | Acesso a dataset |
| `RefreshDataset` | Refresh manual de dataset |

> A lista completa está na [documentação Microsoft](https://learn.microsoft.com/power-bi/admin/service-admin-auditing#activities-audited-by-power-bi).

---

## Output gerado

```
output/20260309_143000/
└── activity_events.csv     # ou .json com --format json
```

**Resumo exibido no terminal:**
```
Total de eventos:       18.432
Dias coletados:         7/7
Usuários únicos:        142
Tipos de atividade:     23

Top atividades:
  ViewReport                          12.543
  ViewDashboard                        3.210
  ExportArtifact                         987
  RefreshDataset                         412
  ShareReport                            280
```

---

## Uso como biblioteca Python

```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import ActivityCollector
from fabricgov.exporters import FileExporter

auth = ServicePrincipalAuth.from_env()

collector = ActivityCollector(
    auth=auth,
    days=7,
    filter_activity="ViewReport",   # opcional
    filter_user=None,               # opcional
    progress_callback=lambda msg: print(msg)
)

result = collector.collect()

print(f"Total: {result['summary']['total_events']} eventos")
print(f"Top atividades: {result['summary']['top_activities'][:3]}")

exporter = FileExporter(format="csv", output_dir="output")
exporter.export(result, [])
```

---

## Erros comuns

**`403 Forbidden`**
- O usuário/SP não tem a role **Fabric Administrator**
- Verifique no Admin Portal do Fabric → Tenant settings → Admin API settings

**`400 Bad Request`**
- `startDateTime` e `endDateTime` não estão no mesmo dia UTC
- Verifique o fuso horário — a API opera sempre em UTC

**Rate limit (`429`)**
- Aguarde ~1 hora e execute novamente
- A coleta de 28 dias consome no mínimo 28 requests

---

**[← Voltar ao README](../README.md)** | **[Coletores →](collectors.md)**
