# Contributing Guide

Thank you for considering contributing to **fabricgov**! This guide will help you understand the project structure and how to add new collectors, exporters, or other improvements.

---

## 📋 Table of Contents

1. [Environment Setup](#-environment-setup)
2. [Project Structure](#-project-structure)
3. [Code Conventions](#-code-conventions)
4. [How to Add a New Collector](#-how-to-add-a-new-collector)
5. [How to Add Tests](#-how-to-add-tests)
6. [Review Process](#-review-process)
7. [Commit Conventions](#-commit-conventions)

---

## 🛠️ Environment Setup

### Prerequisites

- Python 3.12+
- Poetry 1.8+
- Git

### Setup
```bash
# Clone the repository
git clone https://github.com/luhborba/fabricgov.git
cd fabricgov

# Install dependencies
poetry install

# Activate the virtual environment
poetry shell

# Run tests
poetry run pytest tests/ -v
```

### Credential Configuration

Create a `.env` file in the project root:
```env
FABRICGOV_TENANT_ID=your-tenant-id
FABRICGOV_CLIENT_ID=your-client-id
FABRICGOV_CLIENT_SECRET=your-client-secret
```

---

## 🏗️ Project Structure
```
fabricgov/
├── fabricgov/
│   ├── auth/                  # Authentication module
│   │   ├── base.py            # AuthProvider protocol
│   │   ├── service_principal.py
│   │   └── device_flow.py
│   ├── cli/                   # CLI via Click
│   │   ├── main.py            # Main `fabricgov` group
│   │   ├── auth.py            # `fabricgov auth` commands
│   │   ├── collect.py         # `fabricgov collect` commands
│   │   └── session.py         # Session management (`collect all`)
│   ├── collectors/            # Data collectors (11 total)
│   │   ├── base.py            # BaseCollector (retry, pagination, rate limiting)
│   │   ├── workspace_inventory.py
│   │   ├── workspace_access.py
│   │   ├── report_access.py
│   │   ├── dataset_access.py
│   │   ├── dataflow_access.py
│   │   ├── refresh_history.py
│   │   ├── refresh_schedule.py
│   │   ├── domain.py
│   │   ├── tag.py
│   │   ├── capacity.py
│   │   └── workload.py
│   ├── exporters/             # Result exporters
│   │   └── file_exporter.py   # JSON/CSV with run_dir support
│   ├── config.py              # Auth preference system
│   ├── progress.py            # ProgressManager (rich)
│   ├── checkpoint.py          # Checkpoint system
│   └── exceptions.py          # Custom exceptions
├── tests/
│   ├── auth/                  # Unit tests for the auth module
│   ├── manual/                # Manual tests for development
│   └── pytest.ini
├── docs/                      # Documentation
│   ├── en/                    # English docs
│   │   ├── authentication.md
│   │   ├── collectors.md
│   │   ├── exporters.md
│   │   ├── limitations.md
│   │   └── contributing.md
│   ├── authentication.md      # Portuguese docs
│   ├── collectors.md
│   ├── exporters.md
│   ├── limitations.md
│   └── contributing.md
├── pyproject.toml             # Dependencies and Poetry configuration
└── README.md
```

---

## 📝 Code Conventions

### Code Style

We follow **PEP 8** with some adaptations:

- **Indentation:** 4 spaces
- **Max line length:** 88 characters (Black default)
- **Imports:** grouped as stdlib → third-party → local
- **Type hints:** required on all public functions

### Formatting
```bash
# Auto-format code
poetry run black fabricgov/ tests/

# Check style
poetry run flake8 fabricgov/ tests/
```

### Docstrings

We use **Google Style** docstrings:
```python
def collect(self) -> dict[str, Any]:
    """
    Runs the full workspace inventory collection.

    Returns:
        Dictionary with workspaces, artifacts, and summary.

    Raises:
        ForbiddenError: if the SP lacks Admin permissions.
        TimeoutError: if the scan exceeds max_poll_time.
    """
    pass
```

---

## 🔧 How to Add a New Collector

### Step 1: Define the Domain

First, identify:
- **Which API will be used?** (Fabric REST, Power BI REST, DAX query)
- **What data will be collected?**
- **What is the recommended frequency?** (daily, weekly, on-demand)

### Step 2: Create the File
```bash
touch fabricgov/collectors/your_collector.py
```

### Step 3: Implement the Collector

**Basic template:**
```python
from typing import Any
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector


class YourCollector(BaseCollector):
    """
    Brief description of what this collector does.

    API used: [API name]
    Main endpoint: [endpoint]

    Usage:
        collector = YourCollector(auth=auth)
        result = collector.collect()
    """

    # Required OAuth2 scope
    SCOPE = "https://api.fabric.microsoft.com/.default"
    # or "https://analysis.windows.net/powerbi/api/.default"

    def __init__(
        self,
        auth: AuthProvider,
        **kwargs
    ):
        """
        Args:
            auth: Authentication provider
        """
        # Set the correct base_url for the API
        super().__init__(
            auth=auth,
            base_url="https://api.fabric.microsoft.com",  # or powerbi.com
            **kwargs
        )

    def collect(self) -> dict[str, Any]:
        """
        Executes data collection.

        Returns:
            Structured dictionary with the collected data.
        """
        # Simple GET example
        response = self._get(
            endpoint="/v1/your-endpoint",
            scope=self.SCOPE,
            params={"$top": 1000}
        )

        # GET with pagination example
        items = self._paginate(
            endpoint="/v1/your-endpoint",
            scope=self.SCOPE,
            params={"$top": 1000}
        )

        # Structure the result
        return {
            "items": items,
            "summary": {
                "total_items": len(items),
                "collection_time": datetime.now().isoformat(),
            }
        }
```

### Step 4: Expose in `__init__.py`

Edit `fabricgov/collectors/__init__.py`:
```python
from fabricgov.collectors.base import BaseCollector
from fabricgov.collectors.workspace_inventory import WorkspaceInventoryCollector
from fabricgov.collectors.your_collector import YourCollector  # Add

__all__ = [
    "BaseCollector",
    "WorkspaceInventoryCollector",
    "YourCollector",  # Add
]
```

### Step 5: Create a Manual Test

Create `tests/manual/test_your_collector.py`:
```python
from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import YourCollector

auth = ServicePrincipalAuth.from_env()
collector = YourCollector(auth=auth)
result = collector.collect()

print(f"Total items: {result['summary']['total_items']}")
```

Run it:
```bash
poetry run python tests/manual/test_your_collector.py
```

### Step 6: Add Documentation

Add a section to `docs/en/collectors.md` describing:
- What the collector does
- Constructor parameters
- Output structure
- Usage examples
- Known limitations

---

## 🧪 How to Add Tests

### Unit Tests

Create `tests/collectors/test_your_collector.py`:
```python
import pytest
from unittest.mock import MagicMock
from fabricgov.collectors import YourCollector


@pytest.fixture(autouse=True)
def mock_http_client(mocker):
    """Mocks the HTTP client to avoid real API calls."""
    mock_client = MagicMock()
    mocker.patch("httpx.Client", return_value=mock_client)
    return mock_client


class TestYourCollector:

    def test_collect_returns_correct_structure(self, mock_http_client):
        """Validates that collect() returns the expected structure."""
        # Arrange
        mock_http_client.get.return_value.json.return_value = {
            "value": [{"id": "item-1", "name": "Item 1"}]
        }
        mock_http_client.get.return_value.status_code = 200

        auth = MagicMock()
        auth.get_token.return_value = "fake-token"

        collector = YourCollector(auth=auth)

        # Act
        result = collector.collect()

        # Assert
        assert "items" in result
        assert "summary" in result
        assert result["summary"]["total_items"] == 1

    def test_collect_raises_on_403(self, mock_http_client):
        """Validates 403 error handling."""
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

        collector = YourCollector(auth=auth)

        # Act & Assert
        from fabricgov.exceptions import ForbiddenError
        with pytest.raises(ForbiddenError):
            collector.collect()
```

Run tests:
```bash
poetry run pytest tests/collectors/test_your_collector.py -v
```

---

## 🔍 Review Process

### Before Opening a Pull Request

1. **Run tests:**
```bash
   poetry run pytest tests/ -v
```

2. **Format code:**
```bash
   poetry run black fabricgov/ tests/
```

3. **Validate type hints:**
```bash
   poetry run mypy fabricgov/
```

4. **Test manually** with real credentials

### Pull Request Checklist

- [ ] Code is formatted (black)
- [ ] Unit tests added and passing
- [ ] Manual test executed successfully
- [ ] Documentation updated (`docs/en/collectors.md` or similar)
- [ ] `__init__.py` updated to expose new modules
- [ ] Commit follows convention (see below)

### What We Look for in a Review

- **Clarity:** Code is easy to understand
- **Reuse:** Makes use of `BaseCollector` features
- **Error handling:** Raises appropriate custom exceptions
- **Performance:** No unnecessary API calls
- **Documentation:** Complete docstrings and usage examples

---

## 📝 Commit Conventions

We follow **Conventional Commits**:
```
<type>(<scope>): <short description>

<optional body>
```

### Types

- `feat` — New feature
- `fix` — Bug fix
- `docs` — Documentation changes
- `test` — Adds or fixes tests
- `refactor` — Refactoring without changing functionality
- `chore` — Maintenance tasks (build, CI, etc.)

### Scopes

- `auth` — Authentication module
- `collectors` — Data collectors
- `exporters` — Exporters
- `cli` — Command-line interface
- `exceptions` — Custom exceptions
- `docs` — Documentation

### Examples
```bash
# New feature
feat(collectors): add CapacityConsumptionCollector

# Bug fix
fix(auth): handle token expiration in ServicePrincipalAuth

# Documentation
docs(collectors): add examples for WorkspaceInventoryCollector

# Tests
test(auth): add unit tests for DeviceFlowAuth

# Refactoring
refactor(collectors): extract pagination logic to BaseCollector

# Maintenance
chore(deps): update msal to 1.35.0
```

---

## 🐛 Reporting Bugs

Open an [issue on GitHub](https://github.com/luhborba/fabricgov/issues) with:

1. **Descriptive title:** "ForbiddenError when collecting workspaces with SP"
2. **Python and fabricgov version**
3. **Steps to reproduce**
4. **Expected vs actual behavior**
5. **Full traceback** (without exposing credentials)

**Template:**
```markdown
### Description
[short description of the problem]

### Environment
- Python: 3.12.2
- fabricgov: 0.6.0
- OS: Ubuntu 24.04

### Reproduction
1. Run `collector.collect()`
2. Observe 403 error

### Expected behavior
Should collect data without error

### Actual behavior
```
ForbiddenError: [403] Access denied...
```

### Additional context
The SP has Tenant.Read.All permissions configured.
```

---

## 💡 Contribution Ideas

Areas where contributions are especially welcome:

### Analyzers (v0.8.0)
- Implement `fabricgov analyze` commands (datasets without owners, external users with sensitive access, workspaces without refresh)
- New governance finding types

### Exporters
- Export to Excel (.xlsx) with multiple sheets
- Azure Blob Storage integration

### Documentation
- More real-world usage examples
- Troubleshooting guide

### Tests
- Increase unit test coverage for collectors
- Integration tests with mocked API

---

## 📞 Contact

- **Issues:** [github.com/luhborba/fabricgov/issues](https://github.com/luhborba/fabricgov/issues)
- **Discussions:** [github.com/luhborba/fabricgov/discussions](https://github.com/luhborba/fabricgov/discussions)

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the **MIT License**.

---

**Thank you for contributing to fabricgov!**

---

**[← Back: Exporters](exporters.md)** | **[Back to README →](../../README.md)**
