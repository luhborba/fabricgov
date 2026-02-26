# fabricgov

> Biblioteca Python para assessment automatizado de governança em ambientes Microsoft Fabric

[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Poetry](https://img.shields.io/badge/poetry-1.8+-purple.svg)](https://python-poetry.org/)
[![PyPI version](https://badge.fury.io/py/fabricgov.svg)](https://pypi.org/project/fabricgov/)
[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

---

## 🎯 O que é?

**fabricgov** automatiza coleta de dados de governança em Microsoft Fabric via CLI ou Python.

**Principais features:**
- 🔍 Inventário completo de workspaces e 27+ tipos de artefatos
- 🔐 Coleta de acessos (workspaces, reports, datasets, dataflows)
- 🔄 Histórico de refresh e agendamentos configurados
- 🏢 Domínios, tags, capacidades e workloads do tenant
- 💾 Sistema de checkpoint para tenants grandes (retoma de onde parou)
- 📊 Export em JSON ou CSV
- ⚡ CLI pronto para uso
- 🛡️ Rate limit handling automático

---

## 📦 Instalação
```bash
# Via pip (recomendado)
pip install fabricgov

# Ou via Poetry
poetry add fabricgov

# CLI fica disponível
fabricgov --help
```

---

## 🚀 Quick Start

### 1. Configure credenciais (`.env`)
```env
FABRICGOV_TENANT_ID=seu-tenant-id
FABRICGOV_CLIENT_ID=seu-client-id
FABRICGOV_CLIENT_SECRET=seu-client-secret
```

> 📘 [Como obter credenciais →](docs/authentication.md)

---

### 2. Use o CLI
```bash
# Testa credenciais
fabricgov auth sp

# Coleta inventário
fabricgov collect inventory

# Coleta acessos (com checkpoint automático)
fabricgov collect workspace-access
fabricgov collect report-access
fabricgov collect dataset-access
fabricgov collect dataflow-access
fabricgov collect all-access   # todos os acessos de uma vez

# Coleta refresh
fabricgov collect refresh-history
fabricgov collect refresh-schedules
fabricgov collect all-refresh   # histórico + agendamentos

# Coleta infraestrutura
fabricgov collect domains
fabricgov collect tags
fabricgov collect capacities
fabricgov collect workloads
```

**Flags disponíveis:**
- `--format json|csv` (padrão: csv)
- `--output DIR` (padrão: output)
- `--resume/--no-resume` (padrão: resume habilitado)

---

### 3. Ou use como biblioteca Python
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exporters import FileExporter

# Autentica
auth = ServicePrincipalAuth.from_env()

# Coleta inventário
collector = WorkspaceInventoryCollector(auth=auth)
result = collector.collect()

# Exporta
exporter = FileExporter(format="csv", output_dir="output")
exporter.export(result, [])
```

---

## 📊 Coletores Disponíveis

| Coletor | O que coleta | Checkpoint |
|---------|--------------|------------|
| `WorkspaceInventoryCollector` | Inventário completo (workspaces + 27 tipos de artefatos) | ✅ |
| `WorkspaceAccessCollector` | Roles (Admin, Member, Contributor, Viewer) | ✅ |
| `ReportAccessCollector` | Permissões em reports | ✅ |
| `DatasetAccessCollector` | Permissões em datasets | ✅ |
| `DataflowAccessCollector` | Permissões em dataflows | ✅ |
| `RefreshHistoryCollector` | Histórico de execuções de datasets e dataflows | — |
| `RefreshScheduleCollector` | Agendamentos configurados (sem chamadas de API) | — |
| `DomainCollector` | Domínios do tenant (hierarquia, sensitivity labels) | — |
| `TagCollector` | Tags do tenant (escopo tenant ou domínio) | — |
| `CapacityCollector` | Capacidades Premium/Fabric (SKU, região, admins) | — |
| `WorkloadCollector` | Workloads de capacidades Gen1 (P-SKU, A-SKU) | — |

> 📘 [Ver exemplos detalhados →](docs/collectors.md)

---

## 💾 Sistema de Checkpoint

Para tenants grandes, o checkpoint salva progresso automaticamente:
```bash
# Execução 1: processa 200 itens, salva checkpoint
fabricgov collect report-access
# ⏹️ Rate limit atingido (429)

# Aguarda ~1h30min

# Execução 2: retoma de onde parou (automático)
fabricgov collect report-access
# ✓ Processa mais 200 itens...
```

**Como funciona:**
1. Detecta rate limit (429)
2. Salva checkpoint automaticamente
3. Encerra script (terminal liberado)
4. Na próxima execução, retoma de onde parou

> 📘 [Entenda limitações de rate limit →](docs/limitations.md)

---

## 🏗️ Arquitetura
```
fabricgov/
├── cli/                # CLI via Click
├── auth/               # ServicePrincipalAuth + DeviceFlowAuth
├── collectors/         # 11 collectors (access, refresh, infraestrutura)
├── exporters/          # JSON/CSV export
├── checkpoint.py       # Sistema de checkpoint
└── exceptions.py       # Exceções customizadas
```

---

## 📊 Exemplo de Output
```
output/
├── inventory_result.json           # Reutilizável entre collectors
├── checkpoint_report_access.json   # Checkpoint (auto-removido ao completar)
└── 20260226_143000/                # Timestamped folder
    ├── summary.json
    ├── workspaces.csv
    ├── reports.csv
    ├── workspace_access.csv
    ├── report_access.csv
    ├── dataset_access.csv
    ├── dataflow_access.csv
    ├── refresh_history.csv
    ├── refresh_schedules.csv
    ├── domains.csv
    ├── tags.csv
    ├── capacities.csv
    ├── workloads.csv
    └── workloads_errors.csv
```

---

## ⚠️ Limitações Conhecidas

### Rate Limiting
- APIs Admin: ~200 requests/hora (não documentado)
- Tenants grandes: múltiplas execuções com pausas de ~1h30min
- Checkpoint permite retomar sem perder progresso

### Personal Workspaces
- Não suportam APIs de usuários (retornam 404)
- Filtrados automaticamente (30-60% dos workspaces em tenants típicos)

### Performance
- 200 workspaces: ~10 min
- 663 reports: ~5h (4 execuções com pausas)
- 2000+ itens: requer coleta agendada

> 📘 [Lista completa de limitações →](docs/limitations.md)

---

## 🗺️ Roadmap

### ✅ v0.3.0 - 2026-02-23
- [x] CLI completo (`fabricgov` command)
- [x] DatasetAccessCollector
- [x] DataflowAccessCollector
- [x] 5 collectors com checkpoint
- [x] Primeira Versão no Pypi

### ✅ v0.4.0 - 2026-02-24
- [x] RefreshHistoryCollector (histórico de execuções)
- [x] RefreshScheduleCollector (agendamentos configurados)
- [x] CLI: `fabricgov collect refresh-history`
- [x] CLI: `fabricgov collect refresh-schedules`
- [x] CLI: `fabricgov collect all-refresh`
- [x] CLI: `fabricgov auth sp` (renomeado de `auth test`)

### ✅ v0.5.0 (Atual)
- [x] DomainCollector (domínios do tenant)
- [x] TagCollector (tags do tenant)
- [x] CapacityCollector (capacidades Premium/Fabric)
- [x] WorkloadCollector (workloads de capacidades Gen1)
- [x] CLI: `fabricgov collect domains/tags/capacities/workloads`
- [x] 11 collectors no total
- [x] CLI: Orquestradores `all-infrastructure`, `all-access`, `all-refresh`, `all`
- [x] CLI: `fabricgov collect all` — coleta completa em sessão única com checkpoint
- [x] CLI: `fabricgov collect status` — status da sessão e checkpoints pendentes
- [x] Progress bars visuais nos coletores de acesso e refresh

### 🎯 v0.6.0
- [ ] Integração com KeyVault

### 🎯 v0.7.0
- [ ] Report HTML

### 🎯 v1.0.0
- [ ] MkDocs para documentação

> 📘 [Ver changelog completo →](CHANGELOG.md)

---

## 📚 Documentação

- **[Autenticação](docs/authentication.md)** — Service Principal setup
- **[Coletores](docs/collectors.md)** — Exemplos e casos de uso
- **[Exportadores](docs/exporters.md)** — Integração com Power BI, Pandas
- **[Limitações](docs/limitations.md)** — Rate limits, performance
- **[Contribuindo](docs/contributing.md)** — Como contribuir

---

## 📄 Licença

MIT License - veja [LICENSE](LICENSE)

---

## 👤 Autor

**Luciano Borba** — Consultor Data Engineering  

---

**⭐ Se este projeto foi útil, considere dar uma estrela no GitHub!**