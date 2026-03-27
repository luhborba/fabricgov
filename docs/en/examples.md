# Usage Examples

Practical use cases for fabricgov, from simple to advanced.

---

## 1. Full governance audit

Collect everything, generate a report, and analyze findings in sequence.

=== "CLI"

    ```bash
    fabricgov auth sp
    fabricgov collect all --days 28
    fabricgov report --open
    fabricgov analyze --lang en
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov

    fg = FabricGov.from_env()
    run_dir = fg.collect.all(days=28, on_progress=print)
    fg.report(output_path=run_dir / "report.en.html", lang="en")

    findings = fg.analyze(source_dir=run_dir, lang="en")
    for f in findings:
        print(f["severity"], f["count"], f["message"])
    ```

---

## 2. Find datasets without an owner

Identify datasets where `configuredBy` is empty — a high governance risk.

=== "CLI"

    ```bash
    fabricgov collect inventory
    fabricgov analyze --lang en
    # Look for CRITICAL findings: "datasets without defined owner"
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov

    fg = FabricGov.from_env()
    fg.collect.inventory()

    findings = fg.analyze(lang="en")
    no_owner = next(
        (f for f in findings if "owner" in f["message"].lower()),
        None
    )
    if no_owner:
        print(f"⚠️  {no_owner['count']} datasets without owner:")
        for d in no_owner["details"]:
            print(f"  - {d['name']} ({d['workspace_name']})")
    ```

---

## 3. Monitor failed refreshes

Check which datasets or dataflows failed in recent executions.

=== "CLI"

    ```bash
    fabricgov collect inventory
    fabricgov collect refresh-history
    fabricgov analyze --lang en
    # HIGH findings: "refreshes with failure in history"
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov
    import pandas as pd

    fg = FabricGov.from_env()
    fg.collect.inventory()
    fg.collect.refresh_history(history_limit=50)

    findings = fg.analyze(lang="en")
    failures = next(
        (f for f in findings if "fail" in f["message"].lower()),
        None
    )
    if failures:
        df = pd.DataFrame(failures["details"])
        print(df[["artifact_name", "workspace_name", "start_time", "status"]])
    ```

---

## 4. Detect external users (#EXT#)

List guest users with access to tenant workspaces.

=== "CLI"

    ```bash
    fabricgov collect inventory
    fabricgov collect workspace-access
    fabricgov analyze --lang en
    # HIGH findings: "external users (#EXT#) with access"
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov

    fg = FabricGov.from_env()
    fg.collect.inventory()
    fg.collect.workspace_access()

    findings = fg.analyze(lang="en")
    external = next(
        (f for f in findings if "#EXT#" in f["message"]),
        None
    )
    if external:
        print(f"{external['count']} external user(s) found:")
        for u in external["details"]:
            print(f"  - {u['email']}  roles: {u['roles']}")
    ```

---

## 5. Weekly snapshot comparison

Detect what changed between two collection runs: new workspaces, removed artifacts, changed access.

=== "CLI"

    ```bash
    # Week 1
    fabricgov collect all --days 7

    # Week 2 (7 days later)
    fabricgov collect all --days 7

    # Automatically compares the 2 most recent runs
    fabricgov diff
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov

    fg = FabricGov.from_env()

    # Auto-detects the 2 most recent runs
    result = fg.diff()
    print("Workspaces:", result.workspaces)
    print("Artifacts:", result.artifacts)
    print("Access:", result.access)
    ```

---

## 6. Board presentation report

Generate PT and EN versions of the report in a specific folder.

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
    print("Reports generated.")
    ```

---

## 7. GitHub Actions integration (CI/CD)

Automated weekly collection with critical findings notification.

```yaml title=".github/workflows/fabricgov.yml"
name: Governance Weekly Scan

on:
  schedule:
    - cron: "0 6 * * 1"  # every Monday at 06:00 UTC
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

## 8. Ad-hoc analysis in Jupyter Notebook

Interactive data exploration with Pandas and Plotly.

```python
from fabricgov import FabricGov
import pandas as pd
import plotly.express as px

# Authenticate and collect
fg = FabricGov.from_device_flow()
run_dir = fg.collect.all(days=7)

# Findings as DataFrame
findings = fg.analyze(source_dir=run_dir, lang="en")
df_findings = pd.DataFrame(findings)[["severity", "count", "message"]]
display(df_findings)

# Chart findings by severity
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
    title="Governance Findings by Severity",
)
fig.show()

# Reading datasets CSV directly
datasets_csv = run_dir / "datasets.csv"
if datasets_csv.exists():
    df_ds = pd.read_csv(datasets_csv)
    no_owner = df_ds[df_ds["configuredBy"].isna() | (df_ds["configuredBy"] == "")]
    print(f"Datasets without owner: {len(no_owner)}")
    display(no_owner[["name", "workspace_name"]].head(20))
```

---

## 9. Filter activity by user or operation

Audit what a specific user did, or which operations were most executed.

=== "CLI"

    ```bash
    # Activity for a specific user over the last 14 days
    fabricgov collect activity \
      --days 14 \
      --filter-user john@company.com

    # Only report view operations
    fabricgov collect activity \
      --days 7 \
      --filter-activity ViewReport
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov
    import pandas as pd

    fg = FabricGov.from_env()

    # Activity for a specific user
    run_dir = fg.collect.activity(
        days=14,
        filter_user="john@company.com",
    )

    # Read the generated CSV
    df = pd.read_csv(run_dir / "activity_events.csv")
    print(df.groupby("Activity")["Id"].count().sort_values(ascending=False))
    ```

---

## 10. Azure Key Vault authentication (production)

For production environments where credentials cannot be stored on disk.

=== "CLI"

    ```bash
    fabricgov auth keyvault \
      --vault-url https://my-vault.vault.azure.net/

    fabricgov collect all --days 28
    ```

=== "Python"

    ```python
    from fabricgov import FabricGov

    fg = FabricGov.from_keyvault(
        vault_url="https://my-vault.vault.azure.net/",
        # Custom secret names (optional):
        # secret_names={
        #     "tenant_id": "my-tenant-id",
        #     "client_id": "my-client-id",
        #     "client_secret": "my-client-secret",
        # }
    )

    run_dir = fg.collect.all(days=28)
    fg.report(output_path=run_dir / "report.en.html", lang="en")
    ```

> See [Key Vault](keyvault.md) to configure secrets in Azure.
