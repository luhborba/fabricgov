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
- 🔐 Coleta de acessos (roles em workspaces, permissões em reports)
- 💾 Sistema de checkpoint para coletas resumíveis em ambientes grandes
- 🔐 Dois modos de autenticação: Service Principal e Device Flow (interativo)
- 📊 Export em JSON ou CSV com estrutura timestampada
- ⚡ Batching automático e progress feedback em tempo real
- 🛡️ Tratamento robusto de erros HTTP e rate limiting

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
└── 20260220_120000/
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
- **[Coletores Disponíveis](docs/collectors.md)** — WorkspaceInventoryCollector, Access Collectors, exemplos
- **[Exportadores](docs/exporters.md)** — Formatos JSON e CSV, estrutura de arquivos
- **[Limitações Técnicas](docs/limitations.md)** — Rate limits, Personal Workspaces, performance
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
│   ├── workspace_inventory.py
│   ├── workspace_access.py
│   └── report_access.py
├── exporters/          # Exportação de resultados
│   └── file_exporter.py
├── checkpoint.py       # Sistema de checkpoint
└── exceptions.py       # Exceções customizadas
```

**Princípios de design:**
- **Desacoplamento:** Coletores não conhecem a implementação de auth
- **Extensibilidade:** Novos coletores herdam retry/paginação do BaseCollector
- **Rastreabilidade:** Cada execução gera pasta timestampada + log completo
- **Resiliência:** Sistema de checkpoint permite retomar coletas interrompidas

---

## 🔧 Coletores Disponíveis

### ✅ WorkspaceInventoryCollector

Coleta inventário completo via Admin Scan API.

**O que coleta:**
- 302 workspaces (em ~24s)
- 27+ tipos de artefatos: datasets, reports, dashboards, dataflows, lakehouses, warehouses, notebooks, etc.
- Datasource instances (configuradas + com erros)

**Características:**
- Batching automático (100 workspaces por lote)
- Polling assíncrono com feedback de progresso
- Metadados completos de cada artefato

> 📘 Veja [docs/collectors.md](docs/collectors.md) para exemplos detalhados.

---

### ✅ WorkspaceAccessCollector

Coleta roles de acesso (Admin, Member, Contributor, Viewer) em workspaces.

**O que coleta:**
- Roles em workspaces (Admin, Member, Contributor, Viewer)
- Usuários e Service Principals com acesso
- Filtragem automática de Personal Workspaces

**Características:**
- Sistema de checkpoint para coletas resumíveis
- Fail fast ao detectar rate limit (não trava terminal)
- Suporta execução em múltiplas sessões

**Limitações:**
- Rate limit: ~200 requests/hora
- Tenants grandes requerem múltiplas execuções

> 📘 Veja [docs/collectors.md](docs/collectors.md) e [docs/limitations.md](docs/limitations.md)

---

### ✅ ReportAccessCollector

Coleta permissões de acesso (Owner, Read, ReadWrite, etc.) em reports.

**O que coleta:**
- Permissões em reports (Owner, Read, ReadWrite, ReadCopy, ReadReshare, ReadExplore)
- Usuários e Service Principals com acesso
- Filtragem automática de reports em Personal Workspaces

**Características:**
- Sistema de checkpoint para coletas resumíveis
- Fail fast ao detectar rate limit
- Processa centenas de reports em múltiplas sessões

**Performance:**
- ~663 reports processados em 4 execuções (~5 horas com pausas)
- 8849 acessos coletados em tenant real

> 📘 Veja [docs/collectors.md](docs/collectors.md) e [docs/limitations.md](docs/limitations.md)

---

## 📊 Exemplo de Output

### Summary
```json
{
  "total_workspaces": 302,
  "total_items": 1368,
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

### Workspace Access
```json
{
  "total_workspaces": 302,
  "personal_workspaces_skipped": 186,
  "workspaces_processed": 116,
  "total_access_entries": 382,
  "users_count": 48,
  "service_principals_count": 7,
  "roles_breakdown": {
    "Admin": 263,
    "Member": 9,
    "Viewer": 15,
    "Contributor": 7
  }
}
```

### Report Access
```json
{
  "total_reports": 777,
  "personal_workspaces_reports_skipped": 114,
  "reports_processed": 663,
  "total_access_entries": 8849,
  "users_count": 54,
  "service_principals_count": 7,
  "permissions_breakdown": {
    "Owner": 7950,
    "Read": 230,
    "ReadCopy": 164,
    "ReadReshare": 15
  }
}
```

---

## 🚀 Coleta com Checkpoint (Ambientes Grandes)

Para tenants com muitos workspaces/reports, o sistema de checkpoint permite coleta em múltiplas sessões:
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import ReportAccessCollector
from fabricgov.exceptions import CheckpointSavedException
import json

# Carrega inventário
with open("output/inventory_result.json") as f:
    inventory_result = json.load(f)

auth = ServicePrincipalAuth.from_env()

try:
    collector = ReportAccessCollector(
        auth=auth,
        inventory_result=inventory_result,
        checkpoint_file="output/checkpoint_report_access.json"
    )
    result = collector.collect()
    print("✓ Coleta completa!")
    
except CheckpointSavedException as e:
    print(f"⏹️  Interrompido: {e.progress}")
    print("Execute novamente após ~1 hora para retomar")
```

**Workflow:**
```bash
# Execução 1 (10:00) - processa 200 reports
poetry run python collect_report_access.py
# ⏹️ Rate limit - aguarde 1h

# Execução 2 (11:30) - processa mais 200 reports  
poetry run python collect_report_access.py
# ⏹️ Rate limit - aguarde 1h

# Execução 3 (13:00) - processa mais 200 reports
poetry run python collect_report_access.py
# ⏹️ Rate limit - aguarde 1h

# Execução 4 (14:30) - completa os últimos 63
poetry run python collect_report_access.py
# ✓ Coleta completa!
```

> 📘 Veja [docs/limitations.md](docs/limitations.md) para detalhes sobre rate limiting.

---

## 🛡️ Tratamento de Erros

A biblioteca trata automaticamente os principais erros HTTP:

| Erro | Exceção | Comportamento |
|------|---------|---------------|
| 400 Bad Request | `BadRequestError` | Falha imediata com mensagem clara |
| 401 Unauthorized | `UnauthorizedError` | Valida credenciais |
| 403 Forbidden | `ForbiddenError` | Indica falta de permissões Admin |
| 404 Not Found | `NotFoundError` | Recurso não existe |
| 429 Rate Limit | `TooManyRequestsError` | Salva checkpoint e encerra (fail fast) |
| 500 Server Error | `InternalServerError` | Retry automático |
| 503 Unavailable | `ServiceUnavailableError` | Retry com delay |

**Personal Workspaces:**
- Automaticamente filtrados antes de fazer chamadas à API
- Evita 404 errors desnecessários
- Reduz consumo de rate limit

Todas as exceções incluem:
- Status HTTP
- Endpoint que falhou
- Response body (primeiros 200 chars)

---

## 🧪 Testes

### Unit Tests
```bash
# Roda todos os testes
poetry run pytest tests/ -v

# Só unit tests (sem integração)
poetry run pytest tests/ -v -m "not integration"
```

### Testes Manuais
```bash
# Inventário via Service Principal
poetry run python tests/manual/collect_inventory.py

# Acessos de workspaces com checkpoint
poetry run python tests/manual/collect_workspace_access.py

# Acessos de reports com checkpoint
poetry run python tests/manual/collect_report_access.py
```

---

## ⚠️ Limitações Conhecidas

### Rate Limiting
- APIs Admin têm limite de ~200 requests/hora (não documentado)
- Tenants grandes requerem múltiplas execuções com pausas de ~1h30min
- Sistema de checkpoint permite retomar coleta de onde parou

### Personal Workspaces
- Personal Workspaces não suportam APIs de usuários
- Filtrados automaticamente pelos access collectors
- Tipicamente 30-60% dos workspaces em tenants corporativos

### Performance
- 200 workspaces: ~10 minutos (sem pausas)
- 663 reports: ~5 horas (4 execuções com pausas de 1h30min)
- 2000+ itens: requer coleta agendada ou distribuída

> 📘 Veja [docs/limitations.md](docs/limitations.md) para lista completa.

---

## 🗺️ Roadmap

### ✅ v0.2 (Atual) - 2026-02-20
- [x] WorkspaceAccessCollector com checkpoint
- [x] ReportAccessCollector com checkpoint
- [x] Sistema de checkpoint para coletas resumíveis
- [x] Fail fast em rate limit
- [x] Filtragem automática de Personal Workspaces
- [x] Scripts de coleta independentes
- [x] Documentação de limitações

### 🚧 v0.3 (Próximo)
- [ ] CapacityConsumptionCollector (via DAX queries)
- [ ] Sample mode para assessments rápidos
- [ ] SecurityAccessCollector para datasets/dashboards
- [ ] Estimativa de tempo restante em coletas

### 📋 v0.4
- [ ] CLI via Click (`fabricgov assess`, `fabricgov auth`)
- [ ] Progress bars visuais
- [ ] Assessment orchestrator (múltiplos coletores)
- [ ] Suporte a Azure Key Vault

### 🎯 v1.0
- [ ] Testes de integração completos
- [ ] Report templates (HTML, Word, PDF)
- [ ] Publicação no PyPI
- [ ] Documentação completa de API

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
Power Tuning

---

## 🔗 Links Úteis

- [Documentação do Microsoft Fabric](https://learn.microsoft.com/fabric/)
- [Power BI REST API](https://learn.microsoft.com/rest/api/power-bi/)
- [Fabric REST API](https://learn.microsoft.com/rest/api/fabric/)
- [MSAL Python](https://github.com/AzureAD/microsoft-authentication-library-for-python)

---

**⭐ Se este projeto foi útil, considere dar uma estrela no GitHub!**