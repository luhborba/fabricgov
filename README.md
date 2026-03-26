# fabricgov

> Biblioteca Python para assessment automatizado de governança em ambientes Microsoft Fabric

> 🇺🇸 **English documentation:** [README.en.md](README.en.md)

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
- 📋 Log de atividades do tenant — até 28 dias de histórico
- 💾 Sistema de checkpoint para tenants grandes (retoma de onde parou)
- 📊 Export em JSON ou CSV
- 📄 Relatório HTML automático com gráficos e findings de governança (PT + EN)
- 🔍 Análise de governança no terminal via `fabricgov analyze` (sem chamadas de API)
- 🔁 Comparação de snapshots via `fabricgov diff` — diff.json com todas as dimensões
- 🔑 Integração com Azure Key Vault — credenciais sem texto plano em disco
- ⚡ CLI pronto para uso
- 🛡️ Rate limit handling automático

---

## 📦 Instalação
```bash
# Instalação padrão
pip install fabricgov

# Com suporte a Azure Key Vault
pip install fabricgov[keyvault]

# Ou via Poetry
poetry add fabricgov

# CLI fica disponível
fabricgov --help
```

---

## 🚀 Quick Start

### 1. Autenticação

Escolha o método conforme seu cenário:

#### Service Principal (automação / CI-CD)
```env
# Copie o template e preencha com suas credenciais
cp .env-example .env
# FABRICGOV_TENANT_ID=seu-tenant-id
# FABRICGOV_CLIENT_ID=seu-client-id
# FABRICGOV_CLIENT_SECRET=seu-client-secret
```
```bash
fabricgov auth sp       # valida as credenciais
```

#### Device Flow (uso manual / desenvolvimento local)
```bash
fabricgov auth device   # abre fluxo interativo no browser (sem .env necessário)
```

#### Azure Key Vault (produção / sem credenciais em disco)
```bash
pip install fabricgov[keyvault]
fabricgov auth keyvault --vault-url https://meu-vault.vault.azure.net/
```

> 📘 [Guia completo de autenticação →](docs/authentication.md) | [Key Vault →](docs/keyvault.md)

#### Permissões necessárias

| Autenticação | Permissão obrigatória | Onde configurar |
|---|---|---|
| Service Principal | `Tenant.Read.All` + `Workspace.ReadWrite.All` (Application) | Azure AD → App Registrations → API Permissions |
| Service Principal | Habilitado nas APIs Admin do Fabric | Portal Admin do Fabric → Configurações do tenant |
| Device Flow | Role **Fabric Administrator** no tenant | Portal Admin do Fabric → Usuários |

> ⚠️ Sem essas permissões, as coletas retornam `403 Forbidden`.

---

### 2. Use o CLI
```bash
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

# Coleta log de atividades
fabricgov collect activity               # últimos 7 dias
fabricgov collect activity --days 28     # máximo histórico (28 dias)

# Coleta completa em sessão única
fabricgov collect all
fabricgov collect all --days 28  # inclui atividades na coleta completa (28 dias)
fabricgov collect status         # status da sessão

# Comparação de snapshots
fabricgov diff                                                  # 2 runs mais recentes
fabricgov diff --from output/20260301_120000 --to output/20260309_143000
```

**Flags disponíveis:**
- `--format json|csv` (padrão: csv)
- `--output DIR` (padrão: output)
- `--resume/--no-resume` (padrão: resume habilitado)

---

### 4. Analise os findings de governança (terminal)
```bash
fabricgov analyze                                         # pasta mais recente em output/
fabricgov analyze --from output/20260227_143000/          # pasta específica
fabricgov analyze --from output/20260227_143000/ --lang en  # mensagens em inglês
```

Exibe findings diretamente no terminal (sem abrir o HTML) e salva `findings.json` na pasta de origem.

---

### 3. Gere o relatório de governança
```bash
fabricgov report                                      # pasta mais recente em output/
fabricgov report --from output/20260227_143000/       # pasta específica
fabricgov report --from output/20260227_143000/ --open  # gera e abre no browser
```

Gera automaticamente dois arquivos HTML standalone:
- `report.html` — Português
- `report.en.html` — English

> 📘 [Guia completo do relatório →](docs/report.md) — seções, fontes de dados e regras aplicadas

---

### 5. Ou use como biblioteca Python

A classe `FabricGov` oferece uma API de alto nível — sem CLI, sem configuração manual de auth/exporters:

```python
from fabricgov import FabricGov

# Autentica via .env (TENANT_ID, CLIENT_ID, CLIENT_SECRET)
fg = FabricGov.from_env()

# Coleta completa em uma pasta de sessão (equivalente ao 'collect all')
run_dir = fg.collect.all(days=28)

# Gera relatório HTML
fg.report(output_path=run_dir / "report.html", lang="pt")

# Compara os dois runs mais recentes
result = fg.diff()

# Findings de governança (sem chamadas de API)
findings = fg.analyze(source_dir=run_dir)
for f in findings:
    print(f["severity"], f["count"], f["message"])
```

> 📘 [Ver documentação completa da Python API →](docs/api.md)

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
| `ActivityCollector` | Log de atividades do tenant (até 28 dias) | — |

> 📘 [Ver exemplos detalhados →](docs/collectors.md) | [Log de atividades →](docs/activity.md)

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
├── collectors/         # 12 collectors (access, refresh, infraestrutura, atividades)
├── exporters/          # JSON/CSV export
├── reporters/          # Report HTML (InsightsEngine + HtmlReporter + template)
├── diff/               # Comparação de snapshots (DiffEngine + comparators)
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
    ├── workloads_errors.csv
    ├── activity_events.csv # Log de atividades do tenant
    ├── report.html         # Relatório de governança (PT)
    ├── report.en.html      # Governance report (EN)
    ├── findings.json       # Findings de governança (fabricgov analyze)
    └── diff.json           # Comparativo com snapshot anterior (fabricgov diff)
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

### ✅ v0.5.0 
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

### ✅ v0.6.0
- [x] Atualização de Documentação interna (pt-BR)

### ✅ v0.6.1
- [x] Documentação em inglês (`docs/en/`)
- [x] README em inglês

### ✅ v0.6.2
- [x] Quick Start com Device Flow e tabela de permissões

### ✅ v0.7.0 — 2026-02-27
- [x] Report HTML standalone gerado via `fabricgov report`
- [x] Duas versões automáticas: PT (`report.html`) + EN (`report.en.html`)
- [x] 10 gráficos Plotly interativos + KPI cards + findings de governança
- [x] Seção dedicada de Workspaces com tabela completa de artefatos

### ✅ v0.8.0
- [x] Identificar datasets sem dono
- [x] Usuários externos com acesso a workspaces
- [x] Workspaces sem refresh há mais de 30 dias
- [x] CLI: `fabricgov analyze` — findings no terminal + `findings.json`

### ✅ v0.8.1
- [x] Correção de erro no relatório HTML (conflito `dict.items` no Jinja2)
- [x] Cards de artefatos colapsáveis com nome, dono, workspace e última modificação
- [x] Tabela "Top Usuários por Artefatos Próprios"
- [x] Layout de gráficos otimizado na seção Inventário
- [x] Arquivo `.env-example` com variáveis documentadas

### ✅ v0.9.0 (Atual) — em desenvolvimento)
- [x] Integração com Azure Key Vault (`fabricgov auth keyvault`)
- [x] `ActivityCollector` — log de atividades do tenant (até 28 dias)
- [x] CLI: `fabricgov collect activity --days N`
- [x] `fabricgov collect all --days N` — inclui atividades na coleta completa
- [x] `fabricgov diff` — comparação de dois snapshots de output (workspaces, artefatos, acesso, refresh, findings)


### 🎯 v1.0.0 (Em desenvolvimento))
- [x] `FabricGov` Python API — facade de alto nível para uso programático sem CLI
- [x] Relatório HTML: seções Atividade e Tendências (Activity/Trends com dados do `activity_events.csv` e `diff.json`)
- [ ] MkDocs para documentação

> 📘 [Ver changelog completo →](CHANGELOG.md)

---

## 📚 Documentação

- **[Python API](docs/api.md)** — Uso programático com a classe `FabricGov`
- **[Autenticação](docs/authentication.md)** — Service Principal, Device Flow, Key Vault
- **[Key Vault](docs/keyvault.md)** — Credenciais sem texto plano em disco
- **[Coletores](docs/collectors.md)** — Exemplos e casos de uso
- **[Atividades](docs/activity.md)** — Log de atividades do tenant
- **[Diff de Snapshots](docs/diff.md)** — Comparação entre dois runs de coleta
- **[Relatório HTML](docs/report.md)** — Seções, fontes de dados e regras de governança
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