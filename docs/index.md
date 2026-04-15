# fabricgov

> Biblioteca Python para assessment automatizado de governança em Microsoft Fabric.

[![PyPI version](https://badge.fury.io/py/fabricgov.svg)](https://pypi.org/project/fabricgov/)
[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## O que é?

**fabricgov** automatiza a coleta de dados de governança no Microsoft Fabric via CLI ou Python. Combina chamadas às APIs do Power BI e Microsoft Fabric para extrair inventário, acessos, refresh, atividades e infraestrutura em arquivos CSV/JSON — prontos para análise e relatórios.

---

## Instalação

```bash
pip install fabricgov
```

Para Azure Key Vault:

```bash
pip install fabricgov[keyvault]
```

---

## Quick Start — CLI

```bash
# 1. Configurar autenticação
fabricgov auth sp

# 2. Coletar tudo
fabricgov collect all --days 7

# 3. Gerar relatório HTML
fabricgov report --open

# 4. Ver findings de governança no terminal
fabricgov analyze
```

## Quick Start — Python

```python
from fabricgov import FabricGov

fg = FabricGov.from_env()
run_dir = fg.collect.all(days=28)
fg.report(output_path=run_dir / "report.html", lang="pt")

findings = fg.analyze(source_dir=run_dir)
for f in findings:
    print(f["severity"], f["count"], f["message"])
```

---

## Funcionalidades

| Funcionalidade | Descrição |
|----------------|-----------|
| **10 coletores ativos** | Inventário, workspace-access, refresh, domínios, tags, capacidades, atividades |
| **Acessos via Scanner API** | `artifact_users` extraído em batch no `inventory` — sem risco de rate limit por artefato (v1.1.0) |
| **Modelos semânticos** | `semantic_models` e `datasources` extraídos automaticamente no `inventory` (v1.1.0) |
| **Relatório HTML** | Standalone com Plotly + Bootstrap 5, PT e EN |
| **`fabricgov analyze`** | Findings de governança no terminal + `findings.json` |
| **`fabricgov diff`** | Comparação de dois snapshots de output |
| **Python API** | Facade `FabricGov` para uso programático sem CLI |
| **Checkpoint** | Retomada automática após rate limit (429) |
| **Azure Key Vault** | Credenciais sem texto plano em disco |

---

## Navegação

- [**Python API**](api.md) — Uso programático com `FabricGov`
- [**Autenticação**](authentication.md) — Service Principal, Device Flow, Key Vault
- [**Coletores**](collectors.md) — Os 12 coletores disponíveis
- [**Atividades**](activity.md) — Log de atividades do tenant
- [**Diff de Snapshots**](diff.md) — Comparação entre runs
- [**Relatório HTML**](report.md) — Seções, fontes e regras de governança
- [**Limitações**](limitations.md) — Rate limits e restrições

---

## Autor

**Luciano Borba** — [GitHub](https://github.com/luhborba) · [LinkedIn](https://linkedin.com/in/luhborba) · [YouTube](https://youtube.com/@luhborba)

Data Engineering Consultant — Microsoft Fabric & Power BI
