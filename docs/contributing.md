# Guia de Contribuição

Obrigado por considerar contribuir com o **fabricgov**! Este guia vai te ajudar a entender a estrutura do projeto e como adicionar novos coletores, exportadores ou melhorias.

---

## 📋 Tabela de Conteúdo

1. [Configuração do Ambiente](#-configuração-do-ambiente)
2. [Estrutura do Projeto](#-estrutura-do-projeto)
3. [Convenções de Código](#-convenções-de-código)
4. [Como Adicionar um Novo Coletor](#-como-adicionar-um-novo-coletor)
5. [Como Adicionar Testes](#-como-adicionar-testes)
6. [Process de Review](#-process-de-review)
7. [Convenções de Commit](#-convenções-de-commit)

---

## 🛠️ Configuração do Ambiente

### Pré-requisitos

- Python 3.12+
- Poetry 1.8+
- Git

### Setup
```bash
# Clone o repositório
git clone https://github.com/luhborba/fabricgov.git
cd fabricgov

# Instala dependências
poetry install

# Ativa o ambiente virtual
poetry shell

# Roda os testes
poetry run pytest tests/ -v
```

### Configuração de Credenciais

Crie um arquivo `.env` na raiz:
```env
FABRICGOV_TENANT_ID=seu-tenant-id
FABRICGOV_CLIENT_ID=seu-client-id
FABRICGOV_CLIENT_SECRET=seu-client-secret
```

---

## 🏗️ Estrutura do Projeto
```
fabricgov/
├── fabricgov/
│   ├── auth/                  # Módulo de autenticação
│   │   ├── base.py            # Protocolo AuthProvider
│   │   ├── service_principal.py
│   │   └── device_flow.py
│   ├── collectors/            # Coletores de dados
│   │   ├── base.py            # BaseCollector (retry, paginação)
│   │   └── workspace_inventory.py
│   ├── exporters/             # Exportadores de resultados
│   │   └── file_exporter.py
│   └── exceptions.py          # Exceções customizadas
├── tests/
│   ├── auth/                  # Unit tests do módulo auth
│   ├── manual/                # Testes manuais para desenvolvimento
│   └── pytest.ini
├── docs/                      # Documentação
│   ├── authentication.md
│   ├── collectors.md
│   ├── exporters.md
│   └── contributing.md
├── pyproject.toml             # Dependências e configuração do Poetry
└── README.md
```

---

## 📝 Convenções de Código

### Estilo de Código

Seguimos **PEP 8** com algumas adaptações:

- **Indentação:** 4 espaços
- **Linha máxima:** 88 caracteres (Black default)
- **Imports:** agrupados por stdlib → third-party → local
- **Type hints:** obrigatórios em funções públicas

### Formatação
```bash
# Formata código automaticamente
poetry run black fabricgov/ tests/

# Verifica estilo
poetry run flake8 fabricgov/ tests/
```

### Docstrings

Usamos **Google Style** para docstrings:
```python
def collect(self) -> dict[str, Any]:
    """
    Executa coleta completa do inventário de workspaces.
    
    Returns:
        Dicionário com workspaces, artefatos e summary.
        
    Raises:
        ForbiddenError: se o SP não tiver permissões Admin.
        TimeoutError: se o scan exceder max_poll_time.
    """
    pass
```

---

## 🔧 Como Adicionar um Novo Coletor

### Passo 1: Definir o Domínio

Primeiro, identifique:
- **Qual API será usada?** (Fabric REST, Power BI REST, DAX query)
- **Quais dados serão coletados?**
- **Qual a frequência recomendada?** (diário, semanal, sob demanda)

### Passo 2: Criar o Arquivo
```bash
touch fabricgov/collectors/seu_coletor.py
```

### Passo 3: Implementar o Coletor

**Template básico:**
```python
from typing import Any
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector


class SeuColetor(BaseCollector):
    """
    Descrição breve do que o coletor faz.
    
    API utilizada: [nome da API]
    Endpoint principal: [endpoint]
    
    Uso:
        collector = SeuColetor(auth=auth)
        result = collector.collect()
    """

    # Scope OAuth2 necessário
    SCOPE = "https://api.fabric.microsoft.com/.default"
    # ou "https://analysis.windows.net/powerbi/api/.default"

    def __init__(
        self,
        auth: AuthProvider,
        **kwargs
    ):
        """
        Args:
            auth: Provedor de autenticação
        """
        # Define a base_url correta para a API
        super().__init__(
            auth=auth,
            base_url="https://api.fabric.microsoft.com",  # ou powerbi.com
            **kwargs
        )

    def collect(self) -> dict[str, Any]:
        """
        Executa a coleta de dados.
        
        Returns:
            Dicionário estruturado com os dados coletados.
        """
        # Exemplo de GET simples
        response = self._get(
            endpoint="/v1/seu-endpoint",
            scope=self.SCOPE,
            params={"$top": 1000}
        )
        
        # Exemplo de GET com paginação
        items = self._paginate(
            endpoint="/v1/seu-endpoint",
            scope=self.SCOPE,
            params={"$top": 1000}
        )
        
        # Estrutura o resultado
        return {
            "items": items,
            "summary": {
                "total_items": len(items),
                "collection_time": datetime.now().isoformat(),
            }
        }
```

### Passo 4: Expor no `__init__.py`

Edita `fabricgov/collectors/__init__.py`:
```python
from fabricgov.collectors.base import BaseCollector
from fabricgov.collectors.workspace_inventory import WorkspaceInventoryCollector
from fabricgov.collectors.seu_coletor import SeuColetor  # Adiciona

__all__ = [
    "BaseCollector",
    "WorkspaceInventoryCollector",
    "SeuColetor",  # Adiciona
]
```

### Passo 5: Criar Teste Manual

Cria `tests/manual/test_seu_coletor.py`:
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import SeuColetor

auth = ServicePrincipalAuth.from_env()
collector = SeuColetor(auth=auth)
result = collector.collect()

print(f"Total de itens: {result['summary']['total_items']}")
```

Testa:
```bash
poetry run python tests/manual/test_seu_coletor.py
```

### Passo 6: Adicionar Documentação

Adiciona seção no `docs/collectors.md` descrevendo:
- O que o coletor faz
- Parâmetros do construtor
- Estrutura do output
- Exemplos de uso
- Limitações conhecidas

---

## 🧪 Como Adicionar Testes

### Unit Tests

Cria `tests/collectors/test_seu_coletor.py`:
```python
import pytest
from unittest.mock import MagicMock
from fabricgov.collectors import SeuColetor


@pytest.fixture(autouse=True)
def mock_http_client(mocker):
    """Mocka o cliente HTTP para não fazer chamadas reais."""
    mock_client = MagicMock()
    mocker.patch("httpx.Client", return_value=mock_client)
    return mock_client


class TestSeuColetor:

    def test_collect_retorna_estrutura_correta(self, mock_http_client):
        """Valida que collect() retorna a estrutura esperada."""
        # Arrange
        mock_http_client.get.return_value.json.return_value = {
            "value": [{"id": "item-1", "name": "Item 1"}]
        }
        mock_http_client.get.return_value.status_code = 200
        
        auth = MagicMock()
        auth.get_token.return_value = "fake-token"
        
        collector = SeuColetor(auth=auth)
        
        # Act
        result = collector.collect()
        
        # Assert
        assert "items" in result
        assert "summary" in result
        assert result["summary"]["total_items"] == 1

    def test_collect_lanca_erro_em_403(self, mock_http_client):
        """Valida tratamento de erro 403."""
        # Arrange
        import httpx
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = '{"error": "Forbidden"}'
        
        mock_http_client.get.return_value = mock_response
        mock_http_client.get.return_value.raise_for_status.side_effect = (
            httpx.HTTPStatusError("Forbidden", request=MagicMock(), response=mock_response)
        )
        
        auth = MagicMock()
        auth.get_token.return_value = "fake-token"
        
        collector = SeuColetor(auth=auth)
        
        # Act & Assert
        from fabricgov.exceptions import ForbiddenError
        with pytest.raises(ForbiddenError):
            collector.collect()
```

Roda os testes:
```bash
poetry run pytest tests/collectors/test_seu_coletor.py -v
```

---

## 🔍 Process de Review

### Antes de Abrir um Pull Request

1. **Roda os testes:**
```bash
   poetry run pytest tests/ -v
```

2. **Formata o código:**
```bash
   poetry run black fabricgov/ tests/
```

3. **Valida type hints:**
```bash
   poetry run mypy fabricgov/
```

4. **Testa manualmente** com credenciais reais

### Pull Request Checklist

- [ ] Código está formatado (black)
- [ ] Unit tests adicionados e passando
- [ ] Teste manual executado com sucesso
- [ ] Documentação atualizada (`docs/collectors.md` ou similar)
- [ ] `__init__.py` atualizado para expor novos módulos
- [ ] Commit segue convenção (ver abaixo)

### O que Esperamos no Review

- **Clareza:** Código fácil de entender
- **Reuso:** Aproveita funcionalidades do `BaseCollector`
- **Tratamento de erros:** Lança exceções customizadas apropriadas
- **Performance:** Não faz chamadas desnecessárias à API
- **Documentação:** Docstrings completas e exemplos de uso

---

## 📝 Convenções de Commit

Seguimos **Conventional Commits**:
```
<tipo>(<escopo>): <descrição curta>

<corpo opcional>
```

### Tipos

- `feat` — Nova funcionalidade
- `fix` — Correção de bug
- `docs` — Mudanças na documentação
- `test` — Adiciona ou corrige testes
- `refactor` — Refatoração sem mudar funcionalidade
- `chore` — Tarefas de manutenção (build, CI, etc.)

### Escopos

- `auth` — Módulo de autenticação
- `collectors` — Coletores de dados
- `exporters` — Exportadores
- `exceptions` — Exceções customizadas
- `cli` — Interface de linha de comando (futuro)

### Exemplos
```bash
# Nova funcionalidade
feat(collectors): add CapacityConsumptionCollector

# Correção de bug
fix(auth): handle token expiration in ServicePrincipalAuth

# Documentação
docs(collectors): add examples for WorkspaceInventoryCollector

# Testes
test(auth): add unit tests for DeviceFlowAuth

# Refatoração
refactor(collectors): extract pagination logic to BaseCollector

# Manutenção
chore(deps): update msal to 1.35.0
```

---

## 🐛 Reportando Bugs

Abra uma [issue no GitHub](https://github.com/luhborba/fabricgov/issues) com:

1. **Título descritivo:** "ForbiddenError ao coletar workspaces com SP"
2. **Versão do Python e fabricgov**
3. **Passos para reproduzir**
4. **Comportamento esperado vs obtido**
5. **Traceback completo** (sem expor credenciais)

**Template:**
```markdown
### Descrição
[descrição curta do problema]

### Ambiente
- Python: 3.12.2
- fabricgov: 0.1.0
- SO: Ubuntu 24.04

### Reprodução
1. Execute `collector.collect()`
2. Observe erro 403

### Comportamento esperado
Deveria coletar os dados sem erro

### Comportamento obtido
```
ForbiddenError: [403] Acesso negado...
```

### Contexto adicional
O SP tem permissões de Tenant.Read.All configuradas.
```

---

## 💡 Sugestões de Contribuição

Áreas onde contribuições são especialmente bem-vindas:

### Novos Coletores
- **CapacityConsumptionCollector** — métricas de CU via DAX
- **SecurityAccessCollector** — roles e permissões detalhadas
- **RefreshMonitoringCollector** — histórico de refresh
- **ConnectionsCollector** — conexões e permissões

### Melhorias de Infraestrutura
- CLI via Click (`fabricgov assess`, `fabricgov auth`)
- Assessment orchestrator (executa múltiplos coletores)
- Suporte a Azure Key Vault para credenciais
- Report template (HTML/Word/PDF)

### Documentação
- Tradução para inglês
- Mais exemplos de uso
- Tutoriais em vídeo
- Troubleshooting guide

### Testes
- Aumentar cobertura de unit tests
- Adicionar testes de integração
- Testes de performance

---

## 📞 Contato

- **Issues:** [github.com/luhborba/fabricgov/issues](https://github.com/luhborba/fabricgov/issues)
- **Discussões:** [github.com/luhborba/fabricgov/discussions](https://github.com/luhborba/fabricgov/discussions)
- **Email:** [seu email se aplicável]

---

## 📄 Licença

Ao contribuir, você concorda que suas contribuições serão licenciadas sob a **Licença MIT**.

---

**Obrigado por contribuir com o fabricgov! 🚀**

---

**[← Voltar: Exportadores](exporters.md)** | **[Voltar ao README →](../README.md)**