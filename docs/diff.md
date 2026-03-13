# fabricgov diff — Comparação de Snapshots

O comando `fabricgov diff` compara dois snapshots de output do fabricgov e gera um arquivo `diff.json` com todas as diferenças encontradas entre os dois momentos.

> O `diff.json` é projetado para ser consumido futuramente pelo `fabricgov report`, adicionando seções de comparativo ao relatório HTML.

---

## O que é comparado?

| Dimensão | O que é detectado |
|----------|-------------------|
| **Workspaces** | Adicionados, removidos e alterados (nome, tipo, estado, capacidade) |
| **Artefatos** | Reports, datasets, dataflows, lakehouses e outros adicionados ou removidos por workspace |
| **Acesso** | Permissões concedidas, revogadas e papéis alterados (4 fontes: workspace, report, dataset, dataflow) |
| **Refresh (schedules)** | Agendamentos adicionados ou removidos |
| **Refresh (health)** | Datasets degradados (mais falhas) ou melhorados (menos falhas) |
| **Findings** | Findings novos, resolvidos e com contagem alterada |

---

## Uso básico

```bash
# Compara automaticamente os 2 runs mais recentes em output/
fabricgov diff

# Snapshots explícitos
fabricgov diff --from output/20260301_120000 --to output/20260309_143000

# Salvar diff em outro local
fabricgov diff --output ~/reports/diff.json
```

---

## Opções disponíveis

| Opção | Padrão | Descrição |
|-------|--------|-----------|
| `--from PATH` | penúltimo run | Snapshot base (o mais antigo) |
| `--to PATH` | último run | Snapshot atual (o mais recente) |
| `--output-dir DIR` | `output` | Diretório raiz onde procurar runs automáticos |
| `--output FILE` | `<to>/diff.json` | Caminho do arquivo diff.json gerado |

---

## Output no terminal

Exibe um resumo executivo com totais por seção:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  fabricgov diff — Resumo Executivo
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Intervalo: 8 dias entre snapshots

  Workspaces    +3 adicionados  -1 removidos  ~2 alterados
  Artefatos     +12 adicionados  -2 removidos
  Acesso        +5 concedidas  -2 revogadas  ~1 papel alterado
  Refresh       ↓ 2 degradados  ↑ 1 melhorado
  Findings      ⚠ 1 novos  ✓ 2 resolvidos

✅ diff.json salvo em: output/20260309_143000/diff.json
```

---

## Estrutura do diff.json

```json
{
  "meta": {
    "snapshot_from": "output/20260301_120000",
    "snapshot_to":   "output/20260309_143000",
    "from_ts": "2026-03-01T12:00:00",
    "to_ts":   "2026-03-09T14:30:00",
    "days_between": 8,
    "generated_at": "2026-03-13T10:00:00"
  },
  "workspaces": {
    "available": true,
    "added":   [{"id": "...", "name": "Novo Workspace", "type": "Workspace", ...}],
    "removed": [...],
    "changed": [{"id": "...", "name": "...", "changes": ["estado: 'Active' → 'Inactive'"]}]
  },
  "artifacts": {
    "available": true,
    "added":   [{"type": "reports", "workspace_id": "...", "artifact_id": "...", "name": "Sales KPI"}],
    "removed": [...]
  },
  "access": {
    "available": true,
    "granted":      [{"source": "workspace_access", "resource_name": "...", "user_email": "...", "role": "Admin"}],
    "revoked":      [...],
    "role_changed": [{"source": "...", "resource_name": "...", "user_email": "...", "role_before": ["Member"], "role_after": ["Admin"]}]
  },
  "refresh": {
    "schedules_available": true,
    "schedules_added":   [{"dataset_id": "...", "dataset_name": "..."}],
    "schedules_removed": [...],
    "health_available": true,
    "degraded": [{"name": "Sales Data", "workspace": "Marketing", "failures_before": 0, "failures_after": 3}],
    "improved": [...]
  },
  "findings": {
    "new":           [...],
    "resolved":      [...],
    "count_changed": [{"severity": "HIGH", "message": "...", "count_before": 2, "count_after": 5, "delta": 3}]
  },
  "summary": {
    "workspaces_added": 3,
    "workspaces_removed": 1,
    "workspaces_changed": 2,
    "artifacts_added": 12,
    "artifacts_removed": 2,
    "access_granted": 5,
    "access_revoked": 2,
    "access_role_changed": 1,
    "schedules_added": 1,
    "schedules_removed": 0,
    "datasets_degraded": 2,
    "datasets_improved": 1,
    "findings_new": 1,
    "findings_resolved": 2,
    "findings_count_changed": 1
  }
}
```

---

## Dependências de dados por seção

| Seção | Arquivos CSV necessários |
|-------|--------------------------|
| `workspaces` | `workspaces.csv` |
| `artifacts` | Todos os CSVs de artefatos (reports, datasets, lakehouses, etc.) |
| `access` | `workspace_access.csv`, `report_access.csv`, `dataset_access.csv`, `dataflow_access.csv` |
| `refresh.schedules` | `refresh_schedules.csv` |
| `refresh.health` | `refresh_history.csv` |
| `findings` | Todos os dados disponíveis (roda InsightsEngine em cada snapshot) |

Se um arquivo não existe em um ou ambos os snapshots, a seção correspondente é marcada como `"available": false` e as listas ficam vazias — sem erro.

---

## Uso como biblioteca Python

```python
from fabricgov.diff import DiffEngine, Snapshot, find_run_dirs

# Auto-detecta os 2 mais recentes
runs = find_run_dirs("output")
snap_from = Snapshot(runs[-2])
snap_to   = Snapshot(runs[-1])

engine = DiffEngine(snap_from, snap_to)
result = engine.run()

# Acessa o resumo
print(result.summary)

# Salva diff.json
from pathlib import Path
result.save(Path("output/diff.json"))

# Ou converte para dict (para integração com outros sistemas)
diff_dict = result.to_dict()
```

---

## Casos de uso

### Auditoria semanal de acessos

```python
from fabricgov.diff import DiffEngine, Snapshot, find_run_dirs

runs = find_run_dirs("output")
result = DiffEngine(Snapshot(runs[-2]), Snapshot(runs[-1])).run()

for entry in result.access["granted"]:
    if "#EXT#" in entry.get("user_email", ""):
        print(f"⚠ Acesso externo concedido: {entry['user_email']} em {entry['resource_name']}")
```

### Detectar degradação de refresh

```python
for ds in result.refresh.get("degraded", []):
    print(f"↓ {ds['name']} ({ds['workspace']}): {ds['failures_before']} → {ds['failures_after']} falhas")
```

### Verificar crescimento do tenant

```python
s = result.summary
print(f"Workspaces: {'+' if s['workspaces_added'] >= s['workspaces_removed'] else ''}{s['workspaces_added'] - s['workspaces_removed']}")
print(f"Artefatos:  {'+' if s['artifacts_added'] >= s['artifacts_removed'] else ''}{s['artifacts_added'] - s['artifacts_removed']}")
```

---

## Erros comuns

| Erro | Causa | Solução |
|------|-------|---------|
| `São necessárias ao menos 2 pastas` | Menos de 2 runs em `output/` | Execute `fabricgov collect all` duas vezes ou use `--from`/`--to` explícitos |
| `Pasta não encontrada` | Caminho passado não existe | Verifique o caminho com `ls output/` |
| Seção com `"available": false` | CSV não presente no snapshot | Execute o collector correspondente antes de gerar o diff |

---

**[← Voltar: Análise de Findings](report.md)** | **[Próximo: Autenticação →](authentication.md)**
