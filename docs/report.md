# Relatório de Governança — Guia Completo

> Documentação do `fabricgov report`: como gerar, o que cada seção mostra, de onde vêm os dados e quais regras são aplicadas.

---

## Geração

```bash
fabricgov report                                       # pasta mais recente em output/
fabricgov report --from output/20260227_143000/        # pasta específica
fabricgov report --from output/20260227_143000/ --open # gera e abre no browser
```

O comando gera dois arquivos HTML standalone na pasta de output:

| Arquivo | Idioma |
|---------|--------|
| `report.html` | Português |
| `report.en.html` | Inglês |

Os arquivos são **autossuficientes** — sem dependência de servidor, compartilháveis por email ou armazenamento em nuvem. Plotly e Bootstrap são carregados via CDN.

> **Dados necessários:** pelo menos um arquivo `.csv` ou `.json` na pasta de output. Seções cujos dados não existem são ocultadas automaticamente.

---

## Seções do Relatório

### 1. Resumo Executivo

Visão geral do tenant em KPI cards coloridos. Disponível sempre que houver qualquer dado.

| KPI | Fonte | Regra |
|-----|-------|-------|
| **Workspaces** | `summary.json` → `total_workspaces`; fallback: `len(workspaces.csv)` | Conta total de workspaces coletados |
| **Total de Artefatos** | `summary.json` → `total_items`; fallback: soma de todos os CSVs de artefatos | Soma de todos os itens em todos os tipos de artefato |
| **Usuários Únicos** | Union de `user_email` em `workspace_access.csv`, `report_access.csv`, `dataset_access.csv`, `dataflow_access.csv` | Endereços de email distintos em todos os arquivos de acesso |
| **Usuários Externos** | Mesmos arquivos de acesso | Emails que contêm `#EXT#` (padrão de convidados Azure AD) |
| **Datasets sem Owner** | `datasets.csv` → coluna `configuredBy` | Linhas com `configuredBy` nulo ou vazio |
| **Taxa de Sucesso de Refresh** | `refresh_history.csv` → coluna `status` | `status == "Completed"` ÷ total de linhas × 100 |
| **Workspaces em Dedicated Capacity** | `workspaces.csv` → coluna `isOnDedicatedCapacity` | Valores `true`, `1` ou `yes` (case-insensitive, sem distinção de tipo) |

**Código de cores dos cards:**
- Azul — métricas de inventário (quantidade)
- Amarelo / Vermelho — métricas de risco (externos, sem owner, falhas)
- Verde — métricas de saúde (taxa de sucesso, dedicated capacity)

---

### 2. Inventário

Visão dos artefatos e workspaces com três gráficos.

#### Gráfico: Artefatos por Tipo (barra horizontal)
- **Fonte:** `summary.json` → `items_by_type`; fallback: contagem de linhas de cada CSV de artefato presente na pasta
- **Regra:** top 12 tipos por quantidade, ordenados decrescente
- **CSVs de artefatos reconhecidos:** `reports`, `datasets`, `dataflows`, `dashboards`, `datamarts`, `lakehouses`, `warehouses`, `notebooks`, `datasourceInstances`, `paginatedReports`, `Eventstream`, `Eventhouse`, `KQLDatabase`, `KQLDashboard`, `Reflex`, `DataPipeline`, `MirroredDatabase`, `SQLAnalyticsEndpoint`

#### Gráfico: Tipos de Workspace (donut)
- **Fonte:** `workspaces.csv` → coluna `type`
- **Regra:** `value_counts()` — distribuição por tipo (`Workspace`, `PersonalGroup`, etc.)

#### Gráfico: Dedicated vs Shared (donut)
- **Fonte:** `workspaces.csv` → coluna `isOnDedicatedCapacity`
- **Regra:** valores `true/1/yes` = Dedicated; demais = Shared

---

### 3. Workspaces — Detalhe Completo

Seção dedicada ao detalhe de todos os workspaces coletados. Requer `workspaces.csv`.

#### KPI cards internos
- Total de Workspaces
- Em Dedicated Capacity
- Em Shared Capacity
- Total de Artefatos

#### Tabela: Todos os Workspaces
- **Fonte:** `workspaces.csv` + contagem cruzada com CSVs de artefatos
- **Colunas:** Nome, Tipo, Estado, Capacidade (Dedicated/Shared), ID da Capacidade, Artefatos
- **Ordenação:** decrescente por contagem de artefatos
- **Como a contagem de artefatos é calculada:** para cada CSV de artefato que contém a coluna `workspace_id`, conta o número de linhas por workspace e acumula

#### Gráfico: Top 10 Workspaces (barra horizontal)
- **Fonte:** cruzamento workspace_id → contagem de linhas nos CSVs de artefatos
- **Regra:** top 10 por total de artefatos; nomes truncados em 35 caracteres

#### Cards: Artefatos por Tipo
- **Fonte:** `artifacts_by_type` (mesmo que seção Inventário)
- Cards individuais para cada tipo com contagem

---

### 4. Acesso & Governança

Análise de permissões e exposição de acesso. Requer pelo menos um arquivo `*_access.csv`.

**Arquivos lidos:**
- `workspace_access.csv` — roles em workspaces
- `report_access.csv` — permissões em reports
- `dataset_access.csv` — permissões em datasets
- `dataflow_access.csv` — permissões em dataflows

#### Gráfico: Distribuição de Roles (donut)
- **Fonte:** `workspace_access.csv` → coluna `role`
- **Regra:** `value_counts()` — mostra Admin, Member, Contributor, Viewer e outros

#### Gráfico: Tipo de Principal (donut)
- **Fonte:** `workspace_access.csv` → coluna `principal_type`
- **Regra:** `value_counts()` — User, Group, App, ServicePrincipal, etc.

#### Tabela: Usuários Externos com Acesso (#EXT#)
- **Fonte:** todos os arquivos `*_access.csv` → coluna `user_email`
- **Regra:** emails que contêm `#EXT#` (convidados Azure AD B2B)
- **Colunas:** Email, Roles (union de todos os arquivos), contagem de workspaces
- **Limite:** top 50 por contagem de workspaces

#### Top 10 Usuários por Acessos
- **Fonte:** `workspace_access.csv`
- **Regra:** `groupby("user_email")["workspace_id"].nunique()` — contagem de workspaces distintos por usuário
- **Colunas:** Email, Workspaces (count)

#### Workspaces com Apenas 1 Usuário (Ponto Único de Falha)
- **Fonte:** `workspace_access.csv`
- **Regra:** `groupby("workspace_id")["user_email"].nunique() == 1` — identifica workspaces onde só um email está listado
- **Limite:** top 20
- **Risco:** se esse usuário sair da organização, o workspace ficará sem administrador

---

### 5. Saúde do Refresh

Análise do histórico de execuções de datasets e dataflows. Requer `refresh_history.csv`.

#### Gráfico: Status de Refresh (donut)
- **Fonte:** `refresh_history.csv` → coluna `status`
- **Cores:** Completed = verde, Failed = vermelho, Unknown/Disabled = cinza/laranja
- **Regra:** `value_counts()` sobre todos os registros do histórico

#### Gráfico: Refreshes por Dia — Últimos 30 Dias (line chart)
- **Fonte:** `refresh_history.csv` → coluna `start_time`
- **Regra:** `pd.to_datetime(start_time)` → agrupado por data; filtra os últimos 30 dias a partir do momento de geração do relatório
- **Registros sem `start_time` válido:** ignorados silenciosamente

#### Tabela: Refreshes com Falha
- **Fonte:** `refresh_history.csv`
- **Regra:** `status in ["Failed", "Error", "Disabled"]` (case-insensitive)
- **Colunas:** Artefato, Workspace, Início, Status, Erro (quando disponível em `service_exception_json`)
- **Limite:** top 50 registros

#### Tabela: Datasets sem Refresh nos Últimos 30 Dias
- **Fonte:** `refresh_history.csv`
- **Regra:** para cada artefato (`artifact_name`), pega o `start_time` mais recente; se for anterior a 30 dias da data de geração, entra nesta lista
- **Limite:** top 50 artefatos

---

### 6. Infraestrutura

Análise de capacidades e workloads do tenant. Requer `capacities.csv`.

#### Tabela: Capacidades
- **Fonte:** `capacities.csv`
- **Colunas disponíveis:** Nome (`displayName`), SKU, Estado (`state`), Região (`region`)

#### Gráfico: Workspaces por Capacidade (barra)
- **Fonte:** `workspaces.csv` → `capacityId`; cross-reference com `capacities.csv` → `displayName`
- **Regra:** `value_counts()` do `capacityId` em workspaces, mapeado para nome da capacidade

#### Gráfico: Capacidades por SKU (barra)
- **Fonte:** `capacities.csv` → coluna `sku`
- **Regra:** `value_counts()` — P1, P2, F2, F64, A1, etc.

#### Workloads por Estado
- **Fonte:** `workloads.csv` → coluna `state`
- **Regra:** `value_counts()` — Enabled, Disabled, Unsupported

> **Nota:** Workloads são coletados apenas para capacidades Gen1 (P-SKU e A-SKU). Capacidades Fabric (F-SKU) não expõem workloads via API.

---

### 7. Domínios do Tenant

Lista de domínios e sub-domínios configurados. Requer `domains.csv`.

- **Fonte:** `domains.csv`
- **Colunas:** Nome (`displayName`), Descrição (`description`), ID do domínio pai (`parentDomainId`)
- **Regra de hierarquia:** se `parentDomainId` é nulo/vazio = **Raiz**; caso contrário = **Sub-domínio**
- **Limite:** top 100 domínios

---

### 8. Findings de Governança

Lista priorizada de alertas gerados automaticamente com base nos dados coletados. Os findings são ordenados por severidade e exibidos mesmo quando os dados são parciais.

| Severidade | Cor | Finding | Regra |
|------------|-----|---------|-------|
| **CRITICAL** | Vermelho | Datasets sem owner | `configuredBy` nulo ou vazio em `datasets.csv` |
| **HIGH** | Laranja | Usuários externos com acesso | Emails com `#EXT#` em qualquer arquivo de acesso |
| **HIGH** | Laranja | Refreshes com falha | `status == "Failed"` em `refresh_history.csv` |
| **MEDIUM** | Azul | Workspaces com 1 único usuário | `nunique(user_email) == 1` por workspace em `workspace_access.csv` |
| **MEDIUM** | Azul | Datasets sem refresh há 30+ dias | Último `start_time` > 30 dias em `refresh_history.csv` |
| **OK** | Verde | Nenhum finding crítico | Exibido apenas quando nenhum finding acima for detectado |

> Findings só aparecem quando os dados necessários estão disponíveis. Se `refresh_history.csv` não foi coletado, findings relacionados a refresh não serão gerados.

---

## Dados Necessários por Seção

| Seção | Arquivo(s) necessário(s) |
|-------|--------------------------|
| Resumo Executivo | Qualquer arquivo da pasta |
| Inventário | `workspaces.csv`, `summary.json` ou CSVs de artefatos |
| Workspaces — Detalhe | `workspaces.csv` |
| Acesso & Governança | `workspace_access.csv` (mínimo) |
| Saúde do Refresh | `refresh_history.csv` |
| Infraestrutura | `capacities.csv` |
| Domínios | `domains.csv` |
| Findings | Qualquer combinação dos acima |

---

## Saída

Dois arquivos HTML são gerados na pasta de origem dos dados (ou na pasta informada via `--output`):

```
output/20260227_143000/
├── report.html         # Português
└── report.en.html      # Inglês
```

O arquivo HTML é **standalone**: todos os gráficos Plotly e o CSS Bootstrap são carregados via CDN. O Plotly JS é incluído uma única vez no `<head>` do documento.

---

## Limitações

- Seções ausentes: se um arquivo de dados não existe, a seção correspondente exibe um aviso discreto ("dados não disponíveis") em vez de erro
- Limites de tabelas: 50 linhas para falhas e datasets desatualizados; 20 para workspaces com 1 usuário; 10 para top workspaces/usuários
- Refresh history: a API do Power BI retorna no máximo os últimos refreshes por dataset (veja [limitações](limitations.md))
- Workloads: disponíveis apenas para capacidades Gen1 (P-SKU, A-SKU)
- Gráficos: requerem conexão com CDN do Plotly e Bootstrap para renderizar corretamente

---

> 📘 [Voltar ao README](../README.md) | [Guia de Coletores](collectors.md) | [Limitações](limitations.md)
