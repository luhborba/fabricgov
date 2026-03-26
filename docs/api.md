# Python API — FabricGov

> 📘 [English version →](en/api.md)

A classe `FabricGov` é uma facade de alto nível para uso do fabricgov de forma programática, sem precisar do CLI. Ideal para scripts, notebooks Jupyter, pipelines e integrações customizadas.

---

## Instalação

```bash
pip install fabricgov
```

Para usar com Azure Key Vault:

```bash
pip install fabricgov[keyvault]
```

---

## Importação

```python
from fabricgov import FabricGov
```

---

## Autenticação

### Service Principal via `.env`

Lê `TENANT_ID`, `CLIENT_ID` e `CLIENT_SECRET` do arquivo `.env` na raiz do projeto (ou variáveis de ambiente):

```python
fg = FabricGov.from_env()
```

### Service Principal via parâmetros

```python
fg = FabricGov.from_params(
    tenant_id="...",
    client_id="...",
    client_secret="...",
)
```

### Device Flow (interativo)

Abre o fluxo de autenticação no browser. Útil para desenvolvimento local ou notebooks:

```python
fg = FabricGov.from_device_flow()
```

### Azure Key Vault

Busca as credenciais do Service Principal diretamente no Key Vault (sem texto plano em disco):

```python
fg = FabricGov.from_keyvault(
    vault_url="https://meu-vault.vault.azure.net/",
    # secret_names opcional — padrão: fabricgov-tenant-id, fabricgov-client-id, fabricgov-client-secret
)
```

> Requer `pip install fabricgov[keyvault]`. Consulte [docs/keyvault.md](keyvault.md) para detalhes.

---

## Coleta

Todos os coletores estão disponíveis em `fg.collect.<método>()`.

### Coleta completa

Equivalente ao `fabricgov collect all`. Cria uma pasta de sessão com timestamp e executa todos os 12 coletores em sequência:

```python
run_dir = fg.collect.all(
    output_dir="output",    # diretório raiz (padrão: "output")
    format="csv",           # "csv" ou "json"
    days=28,                # dias de histórico de atividades (0 = pula)
    history_limit=100,      # máximo de refreshes por artefato
    resume=True,            # retomar de checkpoint em rate limit
    on_progress=print,      # callback opcional para log de progresso
)
# Retorna: Path("output/20260313_120000/")
```

### Coletores individuais

```python
# Inventário (deve ser o primeiro)
fg.collect.inventory(output_dir="output", format="csv")

# Acessos (requerem inventory)
fg.collect.workspace_access(output_dir="output")
fg.collect.report_access(output_dir="output")
fg.collect.dataset_access(output_dir="output")
fg.collect.dataflow_access(output_dir="output")

# Refresh
fg.collect.refresh_history(output_dir="output", history_limit=100)
fg.collect.refresh_schedules(output_dir="output")

# Infraestrutura
fg.collect.domains(output_dir="output")
fg.collect.tags(output_dir="output")
fg.collect.capacities(output_dir="output")
fg.collect.workloads(output_dir="output")

# Atividades
fg.collect.activity(
    days=7,
    filter_activity="ViewReport",  # opcional
    filter_user="user@empresa.com", # opcional
)
```

> **Rate limit:** Se atingir o limite de 429, `CheckpointSavedException` é lançada. Execute novamente com `resume=True` para retomar.

---

## Relatório HTML

Gera o relatório HTML de governança a partir dos CSVs coletados:

```python
# A partir do run mais recente em output/
fg.report(output_path="reports/governance.html", lang="pt")
fg.report(output_path="reports/governance.en.html", lang="en")

# A partir de uma pasta específica
fg.report(
    output_path="reports/governance.html",
    source_dir="output/20260313_120000",
    lang="pt",
)
```

> Retorna o `Path` do arquivo HTML gerado.

---

## Diff de Snapshots

Compara dois runs de coleta e gera `diff.json`:

```python
# Auto-detecta os 2 runs mais recentes em output/
result = fg.diff()

# Explícito
result = fg.diff(
    from_dir="output/20260301_120000",
    to_dir="output/20260309_143000",
)

# Salvar em caminho customizado
result = fg.diff(save_to="reports/diff.json")
```

O `DiffResult` retornado tem os atributos `workspaces`, `artifacts`, `access`, `refresh` e `findings`.

> Consulte [docs/diff.md](diff.md) para detalhes da estrutura do `diff.json`.

---

## Análise de Governance (offline)

Retorna os findings de governança sem fazer chamadas de API — lê apenas os CSVs:

```python
findings = fg.analyze(
    source_dir="output/20260313_120000",  # omitir = mais recente
    lang="pt",        # "pt" ou "en"
    save_to="output/20260313_120000/findings.json",  # opcional
)

for f in findings:
    print(f["severity"], f["count"], f["message"])
    for detail in f.get("details", []):
        print(" -", detail)
```

**Estrutura de cada finding:**

| Campo | Tipo | Descrição |
|-------|------|-----------|
| `severity` | `str` | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"OK"` |
| `count` | `int` | Número de itens afetados |
| `message` | `str` | Mensagem no idioma selecionado |
| `message_en` | `str` | Mensagem em inglês (sempre presente) |
| `details` | `list[dict]` | Itens afetados (até 100 por finding) |

---

## Exemplo completo

```python
from fabricgov import FabricGov

fg = FabricGov.from_env()

# 1. Coleta completa
run_dir = fg.collect.all(days=28, on_progress=print)

# 2. Relatório HTML
fg.report(output_path=run_dir / "report.html", lang="pt")
fg.report(output_path=run_dir / "report.en.html", lang="en")

# 3. Diff com run anterior
try:
    diff = fg.diff(to_dir=run_dir)
    print(f"Workspaces: {diff.workspaces}")
except FileNotFoundError:
    print("Apenas 1 run disponível — diff ignorado.")

# 4. Findings
findings = fg.analyze(source_dir=run_dir, lang="pt")
critical = [f for f in findings if f["severity"] == "CRITICAL"]
if critical:
    print(f"⚠️  {len(critical)} finding(s) crítico(s)!")
    for f in critical:
        print(f"  → {f['message']}")
```

---

## Uso em notebook Jupyter

```python
from fabricgov import FabricGov
import pandas as pd

fg = FabricGov.from_device_flow()
run_dir = fg.collect.all(days=7)

findings = fg.analyze(source_dir=run_dir)
df = pd.DataFrame(findings)[["severity", "count", "message"]]
display(df)
```

---

## Referência rápida

| Método | Descrição |
|--------|-----------|
| `FabricGov.from_env()` | Auth via `.env` |
| `FabricGov.from_params(t, c, s)` | Auth via parâmetros |
| `FabricGov.from_device_flow()` | Auth interativa |
| `FabricGov.from_keyvault(url)` | Auth via Key Vault |
| `fg.collect.all(days=28)` | Coleta completa |
| `fg.collect.inventory()` | Inventário de workspaces |
| `fg.collect.activity(days=7)` | Log de atividades |
| `fg.report(path, lang)` | Gera relatório HTML |
| `fg.diff(from_dir, to_dir)` | Compara snapshots |
| `fg.analyze(source_dir, lang)` | Findings offline |
