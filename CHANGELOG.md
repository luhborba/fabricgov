# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [1.1.0] - 2026-04-15

### Added
- `feat(inventory)`: `WorkspaceInventoryCollector.collect()` agora retorna três novas chaves extraídas diretamente do resultado da Scanner API:
  - `artifact_users` — lista plana de usuários por artefato, com campo `accessRight` normalizado (suporta todos os tipos de artefato Fabric + Power BI)
  - `datasources` — lista plana de datasources utilizados por cada dataset, com tratamento de `datasourceInstanceId` como dict ou string opaca
  - `semantic_models` — estrutura hierárquica por dataset: tabelas, colunas, medidas, relacionamentos e expressões DAX/M
- `feat(inventory)`: constante `ARTIFACT_TYPES_WITH_USERS` — tupla com 22 tipos de artefatos que suportam o campo `users` na Scanner API
- `feat(inventory)`: `summary` agora inclui `total_artifact_users`, `total_datasources` e `total_semantic_models`

### Changed
- `refactor(inventory)`: `_list_all_workspaces()` agora filtra por `type == "Workspace"`, excluindo PersonalGroup e outros tipos que não são workspaces reais
- `deprecate`: `ReportAccessCollector`, `DatasetAccessCollector` e `DataflowAccessCollector` marcados como deprecated — use `WorkspaceInventoryCollector` com `getArtifactUsers=True` (ativo por padrão)

### Removed
- `breaking(cli)`: comandos `report-access`, `dataset-access` e `dataflow-access` removidos do CLI — os dados de acesso por artefato já estão disponíveis em `artifact_users` após `fabricgov collect inventory`
- `breaking(api)`: `ReportAccessCollector`, `DatasetAccessCollector` e `DataflowAccessCollector` removidos do `fabricgov.collectors.__all__` (arquivos mantidos por compatibilidade retroativa)
- `chore(cli)`: `all-access` agora executa apenas `workspace-access`

---

## [1.0.4] - 2026-04-06

### Changed
- `chore`: remove referências à empresa "Power Tuning" do relatório HTML, docs (PT + EN) e arquivo de contexto do projeto — o projeto é independente

---

## [1.0.3] - 2026-04-06

### Changed
- `chore`: bump version para 1.0.3 — inclui commits de CHANGELOG, README (PT + EN) e `pyproject.toml` ausentes na release anterior

---

## [1.0.2] - 2026-04-06

### Added
- `feat(collect)`: exibe estimativa de ciclos restantes no resumo da sessão (`collect all`) — usuário sabe quantas rodadas adicionais serão necessárias para concluir

### Fixed
- `fix(collect)`: remove checkpoint obsoleto ao pular sub-coletor já concluído — evita retomadas desnecessárias em execuções subsequentes

---

## [1.0.1] - 2026-03-28

### Fixed
- `fix(checkpoint)`: guard contra `None` checkpoint ao atingir rate limit (429) — evita crash quando checkpoint está ausente
- `fix(checkpoint)`: corrige lógica do `inner_resume` para retomar corretamente sub-coletores internos após pausa por rate limit

---

## [1.0.0] - 2026-03-27

### Added

#### MkDocs — Documentação oficial
- Site de documentação com **MkDocs Material** em PT e EN via plugin `mkdocs-static-i18n`
- Navegação com abas: **Guia CLI**, **Guia Python**, **Exemplos**, **Referência**
- Página inicial (`docs/index.md` / `docs/en/index.md`) com quick start CLI + Python
- Página de exemplos (`docs/examples.md` / `docs/en/examples.md`) — 10 cenários práticos com tabs CLI/Python: auditoria completa, datasets sem owner, refreshes com falha, usuários externos, comparação semanal, relatório para board, GitHub Actions, Jupyter Notebook, filtro de atividades, Key Vault
- CSS customizado: cor da barra `#263238`, logo 48px, cores de destaque visíveis no modo escuro
- Logo `docs/assets/logo-fabricgov.png`
- Grupo de dependências `[tool.poetry.group.docs]`: `mkdocs`, `mkdocs-material`, `mkdocs-static-i18n`

### Changed
- `pyproject.toml`: campo `documentation` atualizado para `https://luhborba.github.io/fabricgov/`
- `README.md` e `README.en.md`: roadmap v1.0.0 marcado como concluído

---

## [0.9.0] - 2026-03-13

### Added

#### Azure Key Vault
- `KeyVaultAuth` em `fabricgov/auth/keyvault.py` — usa `DefaultAzureCredential` (az login, Managed Identity, env vars)
- CLI: `fabricgov auth keyvault --vault-url <URL>` — credenciais do Service Principal sem texto plano em disco
- `save_keyvault_config()` / `get_keyvault_config()` em `config.py` — salva apenas URL + nomes dos secrets
- Extra opcional `fabricgov[keyvault]` (`azure-keyvault-secrets` + `azure-identity`)
- Documentação: `docs/keyvault.md` e `docs/en/keyvault.md`
- Seção Key Vault em `docs/authentication.md` e `docs/en/authentication.md` com tabela comparativa dos 3 métodos

#### ActivityCollector
- **`ActivityCollector`** — coleta o log de atividades do tenant via `GET /v1.0/myorg/admin/activityevents`
  - Iteração dia a dia de `hoje - N` até ontem (janela UTC obrigatória por request)
  - Paginação via `continuationToken`
  - Parâmetros: `days` (padrão: 7, max: 28), `filter_activity`, `filter_user`
  - Summary com `top_activities`, `unique_users`, `days_collected`, `days_with_errors`
- CLI: `fabricgov collect activity [--days N] [--filter-activity X] [--filter-user Y]`
- `fabricgov collect all --days N` — inclui ActivityCollector como Passo 5 (0 = skip)
- `session.py`: `"activity"` adicionado à lista `STEPS`
- `FileExporter`: suporte à chave `activity_events`
- Documentação: `docs/activity.md` e `docs/en/activity.md`

#### fabricgov diff — Comparação de Snapshots
- **`fabricgov diff`** — compara dois snapshots de output e gera `diff.json`
  - Auto-detecta os 2 runs mais recentes em `output/` ou aceita `--from`/`--to` explícitos
  - Compara 5 dimensões: workspaces, artefatos, acesso (4 fontes), refresh (schedules + health), findings
  - `DiffEngine` orquestra comparators independentes → `DiffResult` dataclass
  - `diff.json` salvo em `<to>/diff.json` por padrão (projetado para consumo futuro pelo `fabricgov report`)
- Resumo executivo com rich no terminal (totais por seção)
- Módulo `fabricgov/diff/`: `snapshot.py`, `engine.py`, `comparators/` (workspace, artifacts, access, refresh, findings)
- Documentação: `docs/diff.md` e `docs/en/diff.md`

#### Python API — FabricGov facade
- **`FabricGov`** — facade de alto nível para uso programático (sem CLI)
  - `FabricGov.from_env()` — autentica via Service Principal lendo `.env`
  - `FabricGov.from_params(tenant_id, client_id, client_secret)` — credenciais diretas
  - `FabricGov.from_device_flow()` — fluxo interativo via browser
  - `FabricGov.from_keyvault(vault_url)` — credenciais via Azure Key Vault
  - `fg.collect.<método>()` — sub-namespace com todos os 12 coletores
  - `fg.collect.all(days=28)` — coleta completa em sequência, retorna Path da sessão
  - `fg.report(output_path, lang)` — gera relatório HTML e salva no caminho indicado
  - `fg.diff(from_dir, to_dir)` — compara dois snapshots, retorna `DiffResult`
  - `fg.analyze(source_dir, lang)` — retorna lista de findings sem chamadas de API
- `fabricgov/__init__.py` expõe `FabricGov` para `from fabricgov import FabricGov`

#### Relatório HTML — Seções Atividade e Tendências
- **Seção Atividade**: KPIs (total eventos, usuários únicos, dias coletados, top operação), gráfico de barras top usuários, gráfico de linha timeline por dia, tabela top artefatos acessados
- **Seção Tendências**: delta KPIs (workspaces, artefatos, acesso), tabelas de acesso adicionado/removido, saúde de refresh no período, findings comparados entre snapshots
- `InsightsEngine`: `_load_activity()` lê `activity_events.csv`; `_load_diff()` lê `diff.json`
- `HtmlReporter`: 3 novos builders de gráfico + 35 novas chaves de tradução PT/EN

### Changed
- `docs/collectors.md` e `docs/en/collectors.md`: total atualizado para 12 coletores, tabela ActivityCollector adicionada
- `README.md` e `README.en.md`: features, CLI, arquitetura, output e roadmap atualizados para v0.9.0

### Fixed
- `pyproject.toml`: corrigido typo `"extralçao"` → `"extração"` na description

---

## [0.8.1] - 2026-03-03

### Fixed
- Corrigido erro `'builtin_function_or_method' object is not iterable` no relatório HTML causado por acesso ambíguo `card.items` no template Jinja2 (conflito com método built-in `dict.items`); corrigido com notação de subscript `card['items']`

### Changed
- Seção Inventário: removido gráfico de barras "Artefatos por Tipo" e tabela "Contagem por Tipo de Artefato" (redundantes com os cards)
- Seção Inventário: gráficos donut reduzidos para `col-lg-3` e gráfico de barras Top Workspaces ampliado para `col-lg-6` — todos na mesma linha
- Cards "Artefatos por Tipo" agora são colapsáveis: ao clicar, exibe tabela com nome, dono, workspace e última modificação (até 300 artefatos por tipo)

### Added
- Nova tabela "Top Usuários por Artefatos Próprios" na seção Workspaces (top 10 por campo `configuredBy`)
- Arquivo `.env-example` com variáveis de ambiente documentadas (SP auth, idioma e Key Vault futuro)

---

## [0.8.0] - 2026-02-27

### Added
- **`fabricgov analyze`** — análise de governança diretamente no terminal
  - Lê os CSVs coletados sem chamadas de API (puro análise offline)
  - Tabela rich com findings priorizados por severidade (CRITICAL, HIGH, MEDIUM, OK)
  - Detalhe por finding: lista as primeiras 10 linhas afetadas no terminal
  - Salva `findings.json` na pasta de origem com detalhe completo (até 100 linhas por finding)
  - Opção `--lang pt|en` para mensagens em português ou inglês
  - Opção `--from PATH` para pasta específica (padrão: mais recente em `output/`)
- **Campo `details`** adicionado em cada finding do `InsightsEngine`
  - `datasets_without_owner` → lista de `{name, workspace_name, id}`
  - `external_users` → lista de `{email, roles, workspace_count}`
  - `failed_refreshes` → lista de `{artifact_name, workspace_name, start_time, status}`
  - `stale_datasets` → lista de `{name, workspace, last_refresh}`
  - `single_user_workspaces` → lista de `{workspace, user_email, role}`
  - Campo retrocompatível: `fabricgov report` e template HTML não são afetados

---

## [0.7.1] - 2026-02-27

### Added
- **`docs/report.md`** — documentação completa do relatório HTML em português
  - Descreve cada seção do relatório, a fonte dos dados e as regras aplicadas
  - Tabelas de requisitos por seção (quais arquivos são necessários)
  - Detalhes de todos os 10 gráficos, 6 tabelas e 5 tipos de findings
- **`docs/en/report.md`** — versão em inglês da documentação do relatório

---

## [0.7.0] - 2026-02-27

### Added
- **`fabricgov report`** — geração de relatório HTML de governança standalone
  - Gera duas versões automaticamente: PT (`report.html`) e EN (`report.en.html`)
  - Arquivo `.html` autossuficiente — sem servidor, compartilhável por email ou storage
  - Seções: Resumo Executivo, Inventário, Workspaces (detalhe completo), Acesso & Governança, Saúde do Refresh, Infraestrutura, Domínios, Findings de Governança
  - 10 gráficos interativos com Plotly (bar charts, donuts, line chart, scatter)
  - KPI cards com classificação visual de risco (azul, amarelo, vermelho, verde)
  - Tabela completa de workspaces ordenada por contagem de artefatos (com scroll)
  - Tabelas de governança: usuários externos, top 10 usuários, refreshes com falha, datasets sem refresh recente
  - Findings de governança priorizados por severidade (CRITICAL, HIGH, MEDIUM, OK)
  - Social links do autor: GitHub, LinkedIn, YouTube, Instagram
  - Opções CLI: `--from PATH`, `--output FILE`, `--open` (abre no browser)
- **`InsightsEngine`** (`fabricgov/reporters/insights.py`)
  - Lê todos os CSVs da pasta dinamicamente (sem lista hardcoded de tipos)
  - Fallback robusto: conta workspaces e artefatos diretamente dos CSVs quando `summary.json` tem formato diferente por collector
  - Suporta múltiplos formatos de `summary.json`
- **`HtmlReporter`** (`fabricgov/reporters/html_reporter.py`)
  - `generate(output_path, lang)` — gera versão em idioma específico
  - `generate_all(output_dir)` — gera PT + EN em uma única operação (1 leitura de dados)
  - i18n via `TRANSLATIONS` dict com 50+ chaves PT/EN embutido
  - Template Jinja2 único compartilhado entre idiomas
- **`fabricgov/reporters/templates/report.html.j2`** — template Bootstrap 5 + Plotly CDN
  - Sidebar de navegação fixa com highlight ativo por scroll
  - Tema Dark Blue gerencial (sidebar azul escuro `#1e3a5f`, conteúdo cinza claro)
  - Layout responsivo (sidebar oculta em mobile)

### Dependencies
- `plotly ^5.0` — gráficos interativos embutidos como div HTML
- `jinja2 ^3.1` — templating do relatório HTML
- `pandas ^2.0` — leitura e processamento dos CSVs coletados

---

## [0.6.2] - 2026-02-27

### Changed
- `README.md` e `README.en.md`: Quick Start expandido com explicação do Device Flow e tabela de permissões necessárias (Service Principal vs Device Flow)

---

## [0.6.1] - 2026-02-27

### Added
- Documentação em inglês: `docs/en/authentication.md`, `docs/en/collectors.md`, `docs/en/exporters.md`, `docs/en/limitations.md`, `docs/en/contributing.md`
- `README.en.md` — README completo em inglês com referência cruzada ao README.md

---

## [0.6.0] - 2026-02-26

### Changed
- Documentação interna atualizada (pt-BR): `docs/authentication.md`, `docs/collectors.md`, `docs/exporters.md`, `docs/limitations.md`, `docs/contributing.md`
- Roadmap reorganizado com versões v0.6.x–v1.0.0

---

## [0.5.0] - 2026-02-26

### Added
- **DomainCollector** — coleta todos os domínios do tenant
  - API: `GET https://api.fabric.microsoft.com/v1/admin/domains`
  - Campos: `id`, `displayName`, `description`, `parentDomainId`, `defaultLabelId`
  - Parâmetro `non_empty_only` para filtrar apenas domínios com workspaces ativos
  - Summary com breakdown: root domains, sub-domains, domains com sensitivity label
- **TagCollector** — coleta todas as tags do tenant
  - API: `GET https://api.fabric.microsoft.com/v1/admin/tags`
  - Suporta paginação via `continuationToken`
  - Achata campo `scope` → `scope_type` e `scope_domain_id` para CSV-friendly output
  - Summary com breakdown: tenant tags vs domain tags
- **CapacityCollector** — coleta todas as capacidades do tenant
  - API: `GET https://api.powerbi.com/v1.0/myorg/admin/capacities`
  - Campos: `id`, `displayName`, `sku`, `state`, `region`, `admins`, `capacityUserAccessRight`, `tenantKeyId`
  - Summary com breakdown por SKU e por região
- **WorkloadCollector** — coleta workloads de capacidades Gen1
  - API: `GET https://api.powerbi.com/v1.0/myorg/capacities/{capacityId}/Workloads`
  - Relevante apenas para capacidades Premium P-SKU e Embedded A-SKU
  - Ignora automaticamente capacidades Fabric F-SKU (Gen2 não suporta esta API)
  - Captura erros por capacidade sem interromper coleta
  - Campos: `capacity_id`, `capacity_name`, `capacity_sku`, `workload_name`, `state`, `max_memory_percentage`
  - Summary com breakdown: enabled, disabled, unsupported, capacidades ignoradas Gen2
- **CLI commands para infraestrutura:**
  - `fabricgov collect domains` — coleta domínios (flag `--non-empty-only`)
  - `fabricgov collect tags` — coleta tags
  - `fabricgov collect capacities` — coleta capacidades
  - `fabricgov collect workloads` — coleta workloads (busca capacidades automaticamente)
  - `fabricgov collect all-infrastructure` — executa todos os 4 em sequência
- **FileExporter** agora detecta e exporta `domains`, `tags`, `capacities`, `workloads` e `workloads_errors`
- **FileExporter** parâmetro `run_dir` — reutiliza pasta existente (sem criar novo timestamp)
- **CLI: `fabricgov collect all`** — orquestrador completo de uma sessão única
  - Executa: inventory → all-infrastructure → all-access → all-refresh
  - Mantém uma única pasta de output por sessão (`output/YYYYMMDD_HHMMSS/`)
  - Se rate limit ocorrer em `all-access`, salva checkpoint e continua para `all-refresh`
  - Flags: `--resume/--no-resume` (retoma sessão anterior), `--limit`, `--progress/--no-progress`
- **CLI: `fabricgov collect status`** — diagnóstico da sessão ativa
  - Exibe passo a passo (inventory, all-infrastructure, all-access, all-refresh) com ícones de status
  - Detecta arquivos de checkpoint pendentes automaticamente
  - Sugere `fabricgov collect all --resume` quando há pendências
- **`session_state.json`** — controle de progresso por sessão
  - Salvo em `output/session_state.json`
  - Status por passo: `not_started`, `completed`, `checkpointed`, `failed`
  - Removido automaticamente quando todos os passos concluem
- **Progress bars visuais** nos coletores de acesso e refresh
  - `WorkspaceAccessCollector`, `ReportAccessCollector`, `DatasetAccessCollector`, `DataflowAccessCollector`, `RefreshHistoryCollector`
  - Parâmetro `progress_manager` (opcional) em todos os 5 collectors
  - CLI flags `--progress/--no-progress` nos 5 comandos individuais e no `all-access`

---

## [0.4.0] - 2026-02-24

### Added
- **RefreshHistoryCollector** — coleta histórico de execuções
  - Datasets: `GET /v1.0/myorg/admin/datasets/{datasetId}/refreshes`
  - Dataflows: `GET /v1.0/myorg/admin/dataflows/{dataflowId}/transactions`
  - Checkpoint support (every 50 artifacts)
  - Configurable history limit (default: 100 refreshes per artifact)
  - Filters Personal Workspaces automatically
  - Calculates duration in seconds for each refresh
- **RefreshScheduleCollector** — extrai agendamentos do inventory
  - No API calls (reads from Admin Scan data)
  - Supports datasets and dataflows
  - Returns schedule configuration (enabled, days, times, timezone)
- **CLI commands for refresh data:**
  - `fabricgov collect refresh-history` — coleta histórico
  - `fabricgov collect refresh-schedules` — extrai agendamentos
  - `fabricgov collect all-refresh` — executa ambos
- **Scripts de teste manual:**
  - `tests/manual/collect_refresh_history.py`
  - `tests/manual/collect_refresh_schedules.py`

### Changed
- **CLI: Renamed `fabricgov auth test` to `fabricgov auth sp`** (more explicit)
- **CLI: Improved main help** with structured examples and categories
- **CLI: Separated `all-access` from `all-refresh`**
  - `all-access` — only access collectors (workspace, report, dataset, dataflow)
  - `all-refresh` — only refresh data (history + schedules)
- **FileExporter** now detects and exports `refresh_history` and `refresh_schedules`

### Documentation
- Updated roadmap in README.md with v0.4.0 complete
- Reorganized future milestones (v0.5.0 through v1.0.0)

## [0.3.0] - 2026-02-23

### Added
- **CLI completo via Click** (`fabricgov` command)
  - `fabricgov auth test` — testa credenciais Service Principal
  - `fabricgov auth device` — autenticação interativa Device Flow
  - `fabricgov collect inventory` — coleta inventário de workspaces
  - `fabricgov collect workspace-access` — coleta roles em workspaces
  - `fabricgov collect report-access` — coleta permissões em reports
  - `fabricgov collect dataset-access` — coleta permissões em datasets
  - `fabricgov collect dataflow-access` — coleta permissões em dataflows
  - `fabricgov collect all-access` — coleta todos os acessos em sequência
  - Flags: `--format json|csv`, `--output DIR`, `--resume/--no-resume`
  - Progress callbacks com timestamps
  - Tratamento de erros user-friendly
- **DatasetAccessCollector** com checkpoint
  - Coleta permissões em datasets via API Admin
  - API: `GET /v1.0/myorg/admin/datasets/{datasetId}/users`
  - Filtragem automática de Personal Workspaces
  - Checkpoint a cada 100 datasets
  - Fail fast em rate limit
- **DataflowAccessCollector** com checkpoint
  - Coleta permissões em dataflows via API Admin
  - API: `GET /v1.0/myorg/admin/dataflows/{dataflowId}/users`
  - Filtragem automática de Personal Workspaces
  - Checkpoint a cada 50 dataflows
  - Fail fast em rate limit
- Scripts de teste manual:
  - `tests/manual/collect_dataset_access.py`
  - `tests/manual/collect_dataflow_access.py`

### Changed
- FileExporter agora detecta e exporta `dataset_access` e `dataflow_access`
- Padronização de comandos CLI: todos access collectors usam sufixo `-access`
- Entry point configurado: `fabricgov` disponível após `poetry install`
- Roadmap reorganizado: v0.3 foca em CLI e collectors, v0.4 em docs e capacity

### Dependencies
- Adicionado `click ^8.1.0` para CLI

### Documentation
- Comandos CLI documentados com exemplos
- Help integrado em todos os comandos (`--help`)

---

## [0.2.0] - 2026-02-20

### Added
- **Checkpoint system** para coletas resumíveis após rate limit
  - Módulo `fabricgov/checkpoint.py` para gerenciar checkpoints
  - Salva progresso a cada 50/100 itens processados
  - Retoma coleta de onde parou em execuções subsequentes
- **WorkspaceAccessCollector** com checkpoint
  - Coleta roles (Admin, Member, Contributor, Viewer) em workspaces
  - Filtragem automática de Personal Workspaces
  - Suporte a checkpoint via parâmetro `checkpoint_file`
  - Fail fast ao detectar rate limit (não tenta 5x)
- **ReportAccessCollector** com checkpoint
  - Coleta permissões (Owner, Read, ReadWrite, etc.) em reports
  - Filtragem automática de reports em Personal Workspaces
  - Suporte a checkpoint via parâmetro `checkpoint_file`
- **CheckpointSavedException** em `fabricgov/exceptions.py`
  - Exceção lançada ao salvar checkpoint por rate limit
  - Contém informações de progresso e caminho do checkpoint
- **Scripts de coleta independentes** em `tests/manual/`
  - `collect_inventory.py` - Coleta inventário e salva JSON
  - `collect_workspace_access.py` - Coleta acessos de workspaces com checkpoint
  - `collect_report_access.py` - Coleta acessos de reports com checkpoint
- **FileExporter** agora detecta e exporta estruturas de access collectors
  - Suporte a `workspace_access` e `workspace_access_errors`
  - Suporte a `report_access` e `report_access_errors`

### Changed
- Access collectors agora param imediatamente ao detectar 429 (fail fast)
- Personal Workspaces são filtrados antes de fazer chamadas à API
- Estratégia de retry: ao invés de tentar 5x com pausa de 30s, salva checkpoint e encerra
- Coleta de acessos pode ser executada de forma isolada (usa `inventory_result.json`)

### Fixed
- Rate limit handling agora não prende terminal por horas
- Personal Workspaces não causam mais 404 errors desnecessários

### Documentation
- Documentação completa de WorkspaceAccessCollector em `docs/collectors.md`
- Documentação completa de ReportAccessCollector em `docs/collectors.md`
- Seção sobre limitações de rate limit e Personal Workspaces
- Exemplos de uso com checkpoint
- Casos de uso práticos (auditoria, workspaces órfãos, etc.)

---

## [0.1.0] - 2026-02-19

### Added
- **Módulo de autenticação** (`fabricgov/auth/`)
  - `ServicePrincipalAuth` - Autenticação via client credentials
    - Suporte a `.env` via `from_env()`
    - Suporte a parâmetros diretos via `from_params()`
  - `DeviceFlowAuth` - Autenticação interativa
    - Multi-tenant automático (usa endpoint `/common`)
    - Client ID público do Azure CLI como padrão
    - Cache de token entre execuções
  - `AuthProvider` protocol para desacoplamento
- **Módulo de coletores** (`fabricgov/collectors/`)
  - `BaseCollector` - Classe base abstrata
    - Retry automático com exponential backoff (429, 500, 503)
    - Rate limiting configurável (`request_delay`)
    - Paginação automática via `continuationToken`
    - Timeout configurável
  - `WorkspaceInventoryCollector` - Inventário completo via Admin Scan API
    - Batching automático (100 workspaces por lote)
    - Polling assíncrono com feedback de progresso
    - Extração de 27+ tipos de artefatos
    - Agregação de datasources (instances + misconfigured)
    - Testado: 302 workspaces, 1367 itens em ~24s
- **Módulo de exportadores** (`fabricgov/exporters/`)
  - `FileExporter` - Exporta para JSON ou CSV
    - Estrutura timestampada: `output/YYYYMMDD_HHMMSS/`
    - `log.txt` com progresso completo
    - `summary.json` sempre em JSON
    - Arquivos individuais por tipo de artefato (só os com dados)
    - CSV com achatamento de objetos aninhados
- **Exceções customizadas** (`fabricgov/exceptions.py`)
  - Hierarquia completa: `FabricGovError` (base)
  - Erros HTTP específicos: `BadRequestError`, `UnauthorizedError`, `ForbiddenError`, `NotFoundError`, `TooManyRequestsError`, `InternalServerError`, `ServiceUnavailableError`
  - `AuthenticationError` para falhas de autenticação
  - Mensagens de erro com contexto (status, endpoint, response body)
- **Documentação completa** (`docs/`)
  - `README.md` - Overview, instalação, quick start, roadmap
  - `docs/authentication.md` - Guia completo de Service Principal e Device Flow
  - `docs/collectors.md` - Documentação do WorkspaceInventoryCollector
  - `docs/exporters.md` - Guia do FileExporter com exemplos de integração
  - `docs/contributing.md` - Como contribuir, convenções, adicionar coletores
- **Testes** (`tests/`)
  - Unit tests do módulo `auth` (19 testes)
  - Testes manuais organizados em `tests/manual/`
  - Fixtures e mocks para MSAL
- **Configuração do projeto**
  - Poetry para gerenciamento de dependências
  - `.gitignore` configurado (output/, checkpoints, .env)
  - Estrutura de pastas organizada

### Dependencies
- `msal ^1.34.0` - Autenticação Microsoft
- `httpx ^0.28.1` - Cliente HTTP
- `python-dotenv ^1.0.1` - Leitura de .env
- `pytest ^8.3.4` - Framework de testes
- `pytest-mock ^3.14.0` - Mocks para testes

### Documentation
- README principal com badges, quick start e roadmap
- Guia de autenticação (SP + Device Flow) com exemplos completos
- Guia de coletores com casos de uso práticos
- Guia de exportadores com exemplos de integração (Pandas, Power BI, Azure)
- Guia de contribuição com convenções e templates

### Performance
- WorkspaceInventoryCollector: 302 workspaces em ~24 segundos
- Batching otimizado para Admin Scan API
- Zero throttling observado em testes com tenant real

### Security
- Suporte a Service Principal com permissions mínimas
- Device Flow com MFA support automático
- Credenciais via .env (não hardcoded)
- Validação de tenant_id no __init__ (catch early)

---

## [0.0.1] - 2026-02-18

### Added
- Estrutura inicial do projeto
- Configuração do Poetry
- Estrutura de pastas (`fabricgov/auth`, `fabricgov/collectors`, etc.)
- Arquivo `pyproject.toml` com dependências base

---

## Convenções de Commit

Este projeto segue [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - Nova funcionalidade
- `fix:` - Correção de bug
- `docs:` - Mudanças na documentação
- `refactor:` - Refatoração sem mudar funcionalidade
- `test:` - Adiciona ou corrige testes
- `chore:` - Tarefas de manutenção (build, CI, etc.)

**Exemplos:**
```
feat(auth): add DeviceFlowAuth with multi-tenant support
fix(collectors): handle 404 errors in Personal Workspaces
docs(collectors): add rate limit guidance and examples
refactor(checkpoint): move logic into collectors
test(auth): add unit tests for ServicePrincipalAuth
chore(deps): update msal to 1.35.0
```

---

## Tipos de Mudanças

- **Added** - Novas funcionalidades
- **Changed** - Mudanças em funcionalidades existentes
- **Deprecated** - Funcionalidades que serão removidas
- **Removed** - Funcionalidades removidas
- **Fixed** - Correções de bugs
- **Security** - Correções de vulnerabilidades

---

## Links Úteis

- [Repositório GitHub](https://github.com/luhborba/fabricgov)
- [Documentação](docs/)
- [Issues](https://github.com/luhborba/fabricgov/issues)
- [Pull Requests](https://github.com/luhborba/fabricgov/pulls)