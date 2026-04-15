# Exemplos de Uso

Cenários práticos de uso do fabricgov, do mais simples ao mais avançado.

---

## 1. Auditoria completa de governança

Coleta tudo, gera relatório e analisa findings em sequência.

=== "CLI"

    ```bash
    fabricgov auth sp
    fabricgov collect all --days 28
    fabricgov report --open
    fabricgov analyze
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov

    fg = FabricGov.from_env()
    run_dir = fg.collect.all(days=28, on_progress=print)
    fg.report(output_path=run_dir / "report.html", lang="pt")

    findings = fg.analyze(source_dir=run_dir)
    for f in findings:
        print(f["severity"], f["count"], f["message"])
    ```

---

## 2. Encontrar datasets sem owner

Identifica datasets onde o campo `configuredBy` está vazio — risco alto de governança.

=== "CLI"

    ```bash
    fabricgov collect inventory
    fabricgov analyze
    # Procure por findings CRITICAL: "datasets sem owner definido"
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov
    import pandas as pd

    fg = FabricGov.from_env()
    fg.collect.inventory()

    findings = fg.analyze()
    sem_owner = next(
        (f for f in findings if "owner" in f["message"].lower()),
        None
    )
    if sem_owner:
        print(f"⚠️  {sem_owner['count']} datasets sem owner:")
        for d in sem_owner["details"]:
            print(f"  - {d['name']} ({d['workspace_name']})")
    ```

---

## 3. Monitorar refreshes com falha

Verifica quais datasets ou dataflows falharam nas últimas execuções.

=== "CLI"

    ```bash
    fabricgov collect inventory
    fabricgov collect refresh-history
    fabricgov analyze --lang pt
    # Findings HIGH: "refreshes com falha no histórico"
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov
    import pandas as pd

    fg = FabricGov.from_env()
    fg.collect.inventory()
    fg.collect.refresh_history(history_limit=50)

    findings = fg.analyze()
    falhas = next(
        (f for f in findings if "falha" in f["message"].lower()),
        None
    )
    if falhas:
        df = pd.DataFrame(falhas["details"])
        print(df[["artifact_name", "workspace_name", "start_time", "status"]])
    ```

---

## 4. Detectar usuários externos (#EXT#)

Lista usuários convidados externos com acesso a artefatos do tenant — workspaces e qualquer tipo de artefato.

=== "CLI"

    ```bash
    fabricgov collect inventory
    fabricgov collect workspace-access
    fabricgov analyze
    # Findings HIGH: "usuários externos (#EXT#) com acesso"
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov

    fg = FabricGov.from_env()
    result_inv = fg.collect.inventory()
    fg.collect.workspace_access()

    # Usuários externos em artefatos (via artifact_users do inventory)
    import json
    from pathlib import Path
    inv = json.loads((Path("output") / "inventory_result.json").read_text())

    externos = [
        u for u in inv["artifact_users"]
        if "#EXT#" in (u.get("emailAddress") or "")
    ]
    print(f"{len(externos)} acesso(s) externo(s) em artefatos:")
    for u in externos[:10]:
        print(f"  - {u['emailAddress']}  {u['artifact_type']}: {u['artifact_name']}")
    ```

---

## 4b. Auditar acessos por tipo de artefato *(v1.1.0)*

Visualiza quem tem acesso a quais Lakehouses, Notebooks ou qualquer tipo de artefato Fabric.

=== "CLI"

    ```bash
    fabricgov collect inventory
    # artifact_users está em inventory_result.json
    ```

=== "Python"

    ```python
    import json, pandas as pd
    from pathlib import Path

    inv = json.loads((Path("output") / "inventory_result.json").read_text())
    df = pd.DataFrame(inv["artifact_users"])

    # Por tipo de artefato
    print(df.groupby("artifact_type")["emailAddress"].nunique().sort_values(ascending=False))

    # Usuários únicos com acesso a Lakehouses
    lh = df[df["artifact_type"] == "Lakehouse"]
    print(f"\nUsuários com acesso a Lakehouses: {lh['emailAddress'].nunique()}")
    print(lh[["emailAddress", "artifact_name", "accessRight"]].drop_duplicates().head(10))
    ```

---

## 5. Comparação semanal de snapshots

Detecta o que mudou entre duas semanas de coleta: novos workspaces, artefatos removidos, acessos alterados.

=== "CLI"

    ```bash
    # Semana 1
    fabricgov collect all --days 7

    # Semana 2 (7 dias depois)
    fabricgov collect all --days 7

    # Compara automaticamente os 2 runs mais recentes
    fabricgov diff
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov

    fg = FabricGov.from_env()

    # Auto-detecta os 2 runs mais recentes
    result = fg.diff()
    print("Workspaces:", result.workspaces)
    print("Artefatos:", result.artifacts)
    print("Acessos:", result.access)
    ```

---

## 6. Relatório para apresentação ao board

Gera versões PT e EN do relatório em uma pasta específica.

=== "CLI"

    ```bash
    fabricgov report \
      --from output/20260313_120000 \
      --output report_board_mar2026.html
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov
    from pathlib import Path

    fg = FabricGov.from_env()
    src = Path("output/20260313_120000")

    fg.report(output_path="reports/board_mar2026.html", source_dir=src, lang="pt")
    fg.report(output_path="reports/board_mar2026.en.html", source_dir=src, lang="en")
    print("Relatórios gerados.")
    ```

---

## 7. Integração com GitHub Actions (CI/CD)

Coleta semanal automatizada com notificação de findings críticos.

```yaml title=".github/workflows/fabricgov.yml"
name: Governance Weekly Scan

on:
  schedule:
    - cron: "0 6 * * 1"  # toda segunda às 06h UTC
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install fabricgov
        run: pip install fabricgov

      - name: Run governance scan
        env:
          TENANT_ID: ${{ secrets.TENANT_ID }}
          CLIENT_ID: ${{ secrets.CLIENT_ID }}
          CLIENT_SECRET: ${{ secrets.CLIENT_SECRET }}
        run: |
          fabricgov collect all --days 7
          fabricgov analyze --lang en

      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: governance-report
          path: output/**/report.en.html
```

---

## 8. Análise ad-hoc em Jupyter Notebook

Exploração interativa dos dados coletados com Pandas e Plotly.

```python
from fabricgov import FabricGov
import pandas as pd
import plotly.express as px

# Autenticação e coleta
fg = FabricGov.from_device_flow()
run_dir = fg.collect.all(days=7)

# Findings como DataFrame
findings = fg.analyze(source_dir=run_dir, lang="pt")
df_findings = pd.DataFrame(findings)[["severity", "count", "message"]]
display(df_findings)

# Gráfico de findings por severidade
fig = px.bar(
    df_findings,
    x="severity", y="count",
    color="severity",
    color_discrete_map={
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#0dcaf0",
        "OK": "#198754",
    },
    title="Findings de Governança por Severidade",
)
fig.show()

# Lendo datasets diretamente
import csv
datasets_csv = run_dir / "datasets.csv"
if datasets_csv.exists():
    df_ds = pd.read_csv(datasets_csv)
    sem_owner = df_ds[df_ds["configuredBy"].isna() | (df_ds["configuredBy"] == "")]
    print(f"Datasets sem owner: {len(sem_owner)}")
    display(sem_owner[["name", "workspace_name"]].head(20))
```

---

## 9. Filtrar atividades por usuário ou operação

Auditar o que um usuário específico fez, ou quais operações foram mais executadas.

=== "CLI"

    ```bash
    # Atividades de um usuário específico nos últimos 14 dias
    fabricgov collect activity \
      --days 14 \
      --filter-user joao@empresa.com

    # Apenas operações de visualização de relatórios
    fabricgov collect activity \
      --days 7 \
      --filter-activity ViewReport
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov
    import pandas as pd

    fg = FabricGov.from_env()

    # Atividades de um usuário
    run_dir = fg.collect.activity(
        days=14,
        filter_user="joao@empresa.com",
    )

    # Lê o CSV gerado
    df = pd.read_csv(run_dir / "activity_events.csv")
    print(df.groupby("Activity")["Id"].count().sort_values(ascending=False))
    ```

---

## 10. Autenticação via Azure Key Vault (produção)

Para ambientes de produção onde credenciais não podem estar em disco.

=== "CLI"

    ```bash
    fabricgov auth keyvault \
      --vault-url https://meu-vault.vault.azure.net/

    fabricgov collect all --days 28
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov

    fg = FabricGov.from_keyvault(
        vault_url="https://meu-vault.vault.azure.net/",
        # Nomes dos secrets customizados (opcional):
        # secret_names={
        #     "tenant_id": "my-tenant-id",
        #     "client_id": "my-client-id",
        #     "client_secret": "my-client-secret",
        # }
    )

    run_dir = fg.collect.all(days=28)
    fg.report(output_path=run_dir / "report.html")
    ```

> Consulte [Key Vault](keyvault.md) para configurar os secrets no Azure.
