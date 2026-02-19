# fabricgov

> Biblioteca Python para assessment automatizado de governança em ambientes Microsoft Fabric

[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Poetry](https://img.shields.io/badge/poetry-1.8+-purple.svg)](https://python-poetry.org/)

---

## 🎯 O que é o fabricgov?

O **fabricgov** automatiza a coleta de dados de governança em ambientes Microsoft Fabric, permitindo que consultores, engenheiros de dados e administradores executem diagnósticos estruturados de forma programática — tanto via CLI quanto como módulo Python.

**Principais funcionalidades:**
- 🔍 Inventário completo de workspaces e 27+ tipos de artefatos
- 🔐 Dois modos de autenticação: Service Principal e Device Flow (interativo)
- 📊 Export em JSON ou CSV com estrutura timestampada
- ⚡ Batching automático e progress feedback em tempo real
- 🛡️ Tratamento robusto de erros HTTP e retry com backoff exponencial

---

## 📦 Instalação

### Requisitos
- Python 3.12+
- Poetry 1.8+ (gerenciador de dependências)

### Instalação via Poetry
```bash
# Clone o repositório
git clone https://github.com/luhborba/fabricgov.git
cd fabricgov

# Instala dependências
poetry install

# Ativa o ambiente virtual
poetry shell
```

---

## 🚀 Quick Start

### 1. Configuração de Credenciais

Crie um arquivo `.env` na raiz do projeto:
```env
FABRICGOV_TENANT_ID=seu-tenant-id
FABRICGOV_CLIENT_ID=seu-client-id
FABRICGOV_CLIENT_SECRET=seu-client-secret
```

> 📘 Veja o [Guia de Autenticação](docs/authentication.md) para detalhes sobre como obter as credenciais.

### 2. Exemplo Básico — Inventário de Workspaces
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exporters import FileExporter

# Autentica via Service Principal
auth = ServicePrincipalAuth.from_env()

# Coleta inventário
collector = WorkspaceInventoryCollector(
    auth=auth,
    progress_callback=lambda msg: print(msg)
)
result = collector.collect()

# Exporta para JSON
exporter = FileExporter(format="json", output_dir="output")
output_path = exporter.export(result, log_messages=[])

print(f"✓ Arquivos exportados em: {output_path}")
```

**Output:**
```
output/
└── 20260219_120000/
    ├── log.txt
    ├── summary.json
    ├── workspaces.json
    ├── reports.json
    ├── datasets.json
    └── ...
```

### 3. Autenticação Interativa (Device Flow)
```python
from fabricgov.auth import DeviceFlowAuth

# Não precisa de tenant_id nem client_id
# Usa client público do Azure CLI e multi-tenant automático
auth = DeviceFlowAuth()

# Na primeira execução, pede autenticação no browser
# Execuções seguintes usam cache de token
```

---

## 📚 Documentação Completa

- **[Guia de Autenticação](docs/authentication.md)** — Service Principal, Device Flow, permissões necessárias
- **[Coletores Disponíveis](docs/collectors.md)** — WorkspaceInventoryCollector, parâmetros, outputs
- **[Exportadores](docs/exporters.md)** — Formatos JSON e CSV, estrutura de arquivos
- **[Contribuindo](docs/contributing.md)** — Como contribuir com o projeto

---

## 🏗️ Arquitetura
```
fabricgov/
├── auth/               # Autenticação (SP + Device Flow)
│   ├── base.py         # Protocolo AuthProvider
│   ├── service_principal.py
│   └── device_flow.py
├── collectors/         # Coletores de dados
│   ├── base.py         # BaseCollector (retry, paginação, rate limiting)
│   └── workspace_inventory.py
├── exporters/          # Exportação de resultados
│   └── file_exporter.py
└── exceptions.py       # Exceções customizadas
```

**Princípios de design:**
- **Desacoplamento:** Coletores não conhecem a implementação de auth
- **Extensibilidade:** Novos coletores herdam retry/paginação do BaseCollector
- **Rastreabilidade:** Cada execução gera pasta timestampada + log completo

---

## 🔧 Coletores Disponíveis

### WorkspaceInventoryCollector

Coleta inventário completo via Admin Scan API.

**O que coleta:**
- 302 workspaces (em ~24s)
- 27+ tipos de artefatos: datasets, reports, dashboards, dataflows, lakehouses, warehouses, notebooks, etc.
- Datasource instances (configuradas + com erros)

**Características:**
- Batching automático (100 workspaces por lote)
- Polling assíncrono com feedback de progresso
- Metadados completos de cada artefato (id, name, createdBy, modifiedBy, etc.)

> 📘 Veja [docs/collectors.md](docs/collectors.md) para exemplos detalhados.

---

## 📊 Exemplo de Output

### Summary
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
  "scan_duration_seconds": 24.0,
  "batches_processed": 4
}
```

### Log.txt (trecho)
```
======================================================================
FABRICGOV - LOG DE EXECUÇÃO
======================================================================

PROGRESSO:
----------------------------------------------------------------------
[16:33:36] Listando workspaces do tenant...
[16:33:36] Encontrados 302 workspaces
[16:33:36] Dividido em 4 lote(s) de até 100 workspaces
[16:33:36] 
--- Lote 1/4 (100 workspaces) ---
[16:33:36] Iniciando scan do lote 1/4...
[16:33:37] Scan iniciado (id: a7590fb0-...)
[16:33:42] Lote 1/4 - Status: Succeeded (5s)
...
```

---

## 🛡️ Tratamento de Erros

A biblioteca trata automaticamente os principais erros HTTP:

| Erro | Exceção | Comportamento |
|------|---------|---------------|
| 400 Bad Request | `BadRequestError` | Falha imediata com mensagem clara |
| 401 Unauthorized | `UnauthorizedError` | Valida credenciais |
| 403 Forbidden | `ForbiddenError` | Indica falta de permissões Admin |
| 404 Not Found | `NotFoundError` | Recurso não existe |
| 429 Rate Limit | `TooManyRequestsError` | Retry com exponential backoff |
| 500 Server Error | `InternalServerError` | Retry automático |
| 503 Unavailable | `ServiceUnavailableError` | Retry com delay |

Todas as exceções incluem:
- Status HTTP
- Endpoint que falhou
- Response body (primeiros 500 chars)

---

## 🧪 Testes

### Unit Tests
```bash
# Roda todos os testes
poetry run pytest tests/ -v

# Só unit tests (sem integração)
poetry run pytest tests/ -v -m "not integration"

# Testes de integração (requerem credenciais reais)
poetry run pytest tests/ -v -m integration
```

### Testes Manuais
```bash
# Inventário via Service Principal
poetry run python tests/manual/test_inventory_sp.py

# Inventário via Device Flow
poetry run python tests/manual/test_inventory_device_flow.py

# Tratamento de erros
poetry run python tests/manual/test_errors_sp_errada.py
```

---

## 🗺️ Roadmap

### ✅ v0.1 (Atual)
- [x] Autenticação (SP + Device Flow)
- [x] BaseCollector (retry, paginação, rate limiting)
- [x] WorkspaceInventoryCollector
- [x] FileExporter (JSON + CSV)
- [x] Tratamento de erros HTTP

### 🚧 v0.2 (Próximo)
- [ ] CapacityConsumptionCollector (via DAX queries)
- [ ] SecurityAccessCollector (roles + permissões)
- [ ] RefreshMonitoringCollector
- [ ] ConnectionsCollector

### 📋 v0.3
- [ ] CLI via Click (`fabricgov assess`, `fabricgov auth`)
- [ ] Assessment orchestrator (múltiplos coletores)

### 🎯 v1.0
- [ ] Documentação completa
- [ ] Testes de integração
- [ ] Publicação no PyPI

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Veja o [Guia de Contribuição](docs/contributing.md) para:
- Estrutura do projeto
- Convenções de código
- Como adicionar novos coletores
- Process de review

---

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## 👤 Autor

**Luciano Borba**  
Consultor de Data Engineering especializado em Microsoft Fabric 


---

## 🔗 Links Úteis

- [Documentação do Microsoft Fabric](https://learn.microsoft.com/fabric/)
- [Power BI REST API](https://learn.microsoft.com/rest/api/power-bi/)
- [Fabric REST API](https://learn.microsoft.com/rest/api/fabric/)
- [MSAL Python](https://github.com/AzureAD/microsoft-authentication-library-for-python)

---

**⭐ Se este projeto foi útil, considere dar uma estrela no GitHub!**