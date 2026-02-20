# Limitações Técnicas e Conhecidas

Este documento lista as limitações técnicas da biblioteca **fabricgov**, incluindo restrições de APIs, performance, e casos de uso não suportados.

---

## 📡 Limitações de API

### Rate Limiting - Power BI Admin APIs

**APIs afetadas:**
- `GET /admin/groups/{groupId}/users` (WorkspaceAccessCollector)
- `GET /admin/reports/{reportId}/users` (ReportAccessCollector)

**Limite observado:** ~200 requests/hora (não documentado oficialmente pela Microsoft)

**Comportamento:**
- Após ~200 requests, a API retorna `429 Too Many Requests`
- O limite parece ser uma **janela deslizante**, não fixo de 1 hora
- Pausar 30 segundos e tentar novamente **não** é suficiente
- Requer pausa de **~1h30min** para resetar completamente

**Impacto:**
- Tenants pequenos (<200 workspaces/reports): sem impacto
- Tenants médios (200-1000): requer 2-5 execuções
- Tenants grandes (1000+): requer múltiplas sessões ao longo de várias horas

**Solução implementada:**
- Sistema de checkpoint automático
- Coleta pode ser retomada em múltiplas execuções
- Scripts param ao detectar rate limit (fail fast)

**Estimativa de tempo:**
| Quantidade | Tempo total | Execuções necessárias |
|------------|-------------|----------------------|
| 100 itens | ~5 min | 1 |
| 200 itens | ~10 min | 1 |
| 500 itens | ~1h (com pausas) | 3 |
| 1000 itens | ~3-5h (com pausas) | 5-7 |
| 2000 itens | ~8-12h (com pausas) | 10-15 |

---

### Personal Workspaces

**Problema:**
Personal Workspaces (formato: `"PersonalWorkspace Nome (email)"`) **não suportam** as seguintes APIs Admin:
- `GET /admin/groups/{groupId}/users`
- `GET /admin/reports/{reportId}/users`

**Comportamento observado:**
- Retornam `404 Not Found` ao tentar buscar usuários
- Em alguns casos, retornam `429 Too Many Requests` (consumindo rate limit desnecessariamente)

**Solução implementada:**
- WorkspaceAccessCollector **filtra automaticamente** Personal Workspaces antes de fazer chamadas
- ReportAccessCollector **filtra automaticamente** reports em Personal Workspaces
- Reduz drasticamente quantidade de requests desnecessários

**Impacto em tenants corporativos:**
- Tenants típicos têm 30-60% de Personal Workspaces
- Exemplo: 302 workspaces totais → 186 Personal (62%) → apenas 116 precisam ser coletados

---

### Admin Scan API - WorkspaceInventoryCollector

**Limite de batching:** 100 workspaces por scan request

**Tempo de processamento:**
- Cada scan leva ~5-10 segundos
- Tenants grandes (500+ workspaces) requerem múltiplos scans em sequência

**Limitação de dados:**
- O scan retorna **snapshot** do momento, não é real-time
- Dados podem estar levemente desatualizados (segundos/minutos)
- Scan não retorna histórico ou métricas temporais

**Campos não retornados pelo scan:**
- Histórico de refresh de datasets
- Consumo de capacidade detalhado
- Logs de auditoria
- Queries executadas

---

## 🔒 Limitações de Permissões

### Service Principal

**Permissões obrigatórias:**
- **Tenant.Read.All** (Application permission)
- **Workspace.ReadWrite.All** (Application permission)
- Service Principal deve estar no grupo **Fabric Administrators**

**O que Service Principal NÃO pode fazer:**
- Acessar workspaces/reports sem permissão explícita (mesmo sendo Admin)
- Ver conteúdo de datasets (dados, queries)
- Executar queries DAX diretamente em datasets (requer contexto de usuário)
- Acessar APIs que requerem delegated permissions (user context)

**Nota sobre Admin APIs:**
- Admin APIs permitem **listar** e **inspecionar** recursos
- Não permitem **executar** ou **modificar** conteúdo de datasets/reports

---

### Device Flow

**Requisitos:**
- Usuário autenticando deve ter role de **Fabric Administrator** no tenant
- Suporta MFA automaticamente
- Requer interação humana (não automatizável)

**Limitações:**
- Token expira em ~1 hora
- Cache de token é local (não persiste entre máquinas)
- Não recomendado para CI/CD ou automação

---

## 💾 Limitações de Checkpoint

### Tamanho de dados

**Checkpoint armazena:**
- Lista de IDs processados
- Dados parciais coletados até o momento

**Potencial problema em tenants muito grandes:**
- Checkpoint pode crescer até vários MB
- Exemplo: 5000 reports com 10 acessos cada = ~50MB de checkpoint
- Carregar/salvar checkpoint pode demorar alguns segundos

**Mitigação:**
- Checkpoint salva apenas IDs e dados parciais, não duplica inventory
- Formato JSON compacto

---

### Invalidação de checkpoint

**Checkpoint é invalidado se:**
- Você re-executa `collect_inventory.py` (gera novos IDs)
- Workspaces/reports são deletados entre execuções
- Estrutura do inventory_result muda

**Sintomas:**
- Checkpoint detectado mas nenhum item pulado
- Coleta processa itens que parecem duplicados

**Solução:**
- Delete manualmente o checkpoint: `rm output/checkpoint_*.json`
- Re-execute a coleta do zero

---

## 📊 Limitações de Performance

### Inventário (WorkspaceInventoryCollector)

**Performance esperada:**
- ~100 workspaces: 5-10 segundos
- ~500 workspaces: 30-60 segundos
- ~1000 workspaces: 1-2 minutos

**Gargalo principal:** tempo de scan da API (não controlável)

---

### Access Collectors

**Performance esperada (COM checkpoint):**
- ~200 itens: 3-5 minutos
- ~500 itens: ~1h (com pausas de rate limit)
- ~1000 itens: ~3-5h (com pausas)

**Performance esperada (SEM checkpoint):**
- Inviável para >200 itens (terminal preso por horas)

---

### Export (FileExporter)

**Performance esperada:**
- JSON: rápido até 100MB
- CSV: pode demorar com datasets grandes (achatamento de objetos)

**Limitações de CSV:**
- Arrays aninhados viram strings JSON (requer parsing manual)
- Objetos profundos geram nomes de colunas longos
- Excel tem limite de ~1M linhas

---

## 🚫 Funcionalidades Não Suportadas

### Coleta de métricas de consumo

**Não implementado (planejado para v0.3):**
- Consumo de CU por workspace/dataset
- Histórico de refresh de datasets
- Queries executadas
- Performance de queries

**Motivo:**
- Requer acesso ao dataset do Capacity Metrics App via DAX
- Complexidade adicional significativa

---

### Modificação de recursos

**fabricgov é READ-ONLY:**
- Não modifica workspaces, reports, datasets
- Não cria, deleta, ou altera permissões
- Não executa refreshes ou queries

**Motivo:** foco em governança e assessment, não automação operacional

---

### Coleta em tempo real

**Limitações:**
- Todos os dados são snapshots pontuais
- Não há streaming ou websockets
- Não há detecção de mudanças em tempo real

**Casos de uso não suportados:**
- Monitoramento contínuo
- Alertas em tempo real
- Dashboards ao vivo

---

### Multi-tenancy

**Limitação atual:**
- Coleta um tenant por vez
- Não há suporte para agregar dados de múltiplos tenants
- Service Principal é específico por tenant

**Workaround:**
- Execute a coleta separadamente para cada tenant
- Agregue os resultados manualmente após export

---

## 🐛 Problemas Conhecidos

### Issue #1: Checkpoint não detectado após timeout longo

**Cenário:**
- Checkpoint salvo
- Aguarda >24 horas
- Próxima execução não detecta checkpoint

**Causa:** inventory_result.json pode estar desatualizado

**Solução:**
- Re-execute `collect_inventory.py`
- Delete checkpoints antigos antes de retomar

---

### Issue #2: Caracteres especiais em nomes de workspaces/reports

**Cenário:**
- Workspaces/reports com emojis, caracteres unicode raros
- CSV pode não renderizar corretamente no Excel

**Solução:**
- Use formato JSON ao invés de CSV
- Ou importe CSV com encoding UTF-8 explícito

---

### Issue #3: Service Principal sem permissões retorna erro genérico

**Cenário:**
- SP não está no grupo Fabric Administrators
- Erro retornado: `403 Forbidden` com mensagem genérica

**Solução:**
- Valide permissões seguindo [docs/authentication.md](authentication.md)
- Aguarde até 15 minutos após adicionar ao grupo (propagação de permissões)

---

## 📝 Limitações Documentadas pela Microsoft

### APIs Admin podem mudar sem aviso

**Microsoft não garante:**
- Estabilidade de APIs Admin (podem mudar a qualquer momento)
- Backward compatibility em mudanças de schema
- Disponibilidade SLA para Admin APIs

**Impacto:**
- fabricgov pode quebrar após atualizações da Microsoft
- Sempre teste em ambiente não-produtivo primeiro

---

### Throttling dinâmico

**Microsoft pode ajustar limites dinamicamente:**
- Rate limits podem variar por tenant
- Horários de pico podem ter limites mais agressivos
- Tenants com histórico de abuso podem ter limites reduzidos

**Impacto:**
- Timing de checkpoint pode variar entre execuções
- Pausas de 1h30min podem não ser suficientes em alguns casos

---

## 🔮 Limitações Planejadas para Remoção

### v0.3 (próxima versão)

**Planejado:**
- CapacityConsumptionCollector (métricas via DAX)
- Suporte a múltiplos Service Principals (parallel collection)
- Sample mode para assessments rápidos

### v0.4

**Planejado:**
- CLI com flags (`--resume`, `--sample-mode`)
- Progress bars visuais
- Estimativa de tempo restante

### v1.0

**Planejado:**
- Suporte a Azure Key Vault
- Report templates (HTML, Word, PDF)
- Assessment orchestrator

---

## 💡 Workarounds e Soluções

### Para tenants muito grandes (2000+ itens)

**Opção 1: Coleta agendada**
- Configure cron job ou Task Scheduler
- Execute overnight
- Resultados disponíveis pela manhã

**Opção 2: Coleta distribuída**
- Use múltiplos Service Principals (não documentado/suportado oficialmente)
- Cada SP coleta subset de workspaces
- Agregue resultados manualmente

**Opção 3: Sample mode (planejado v0.3)**
- Coleta apenas amostra estatística
- Rápido (~15 min) para qualquer tamanho
- Precisão ~95%

---

## 📞 Reportar Limitações

Se você encontrou uma limitação não documentada:

1. Verifique se já está listada neste documento
2. Abra uma [Issue no GitHub](https://github.com/luhborba/fabricgov/issues)
3. Inclua:
   - Descrição da limitação
   - Ambiente (tamanho do tenant, tipo de coleta)
   - Output/erro completo
   - Passos para reproduzir

---

**[← Voltar ao README](../README.md)**