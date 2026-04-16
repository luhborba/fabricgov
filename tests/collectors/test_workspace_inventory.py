import pytest
from unittest.mock import MagicMock
from fabricgov.collectors.workspace_inventory import WorkspaceInventoryCollector


@pytest.fixture
def mock_auth():
    auth = MagicMock()
    auth.get_token.return_value = "fake-token"
    return auth


@pytest.fixture
def collector(mock_auth):
    c = WorkspaceInventoryCollector(auth=mock_auth)
    c._datasource_instances = []
    c._misconfigured_datasource_instances = []
    return c


# ── _list_all_workspaces ──────────────────────────────────────────────────────

class TestListAllWorkspaces:
    def test_filtra_personal_group(self, mock_auth, mocker):
        mocker.patch.object(
            WorkspaceInventoryCollector,
            "_paginate",
            return_value=[
                {"id": "ws-1", "name": "Workspace A", "type": "Workspace"},
                {"id": "pg-1", "name": "Personal Group", "type": "PersonalGroup"},
                {"id": "ws-2", "name": "Workspace B", "type": "workspace"},
            ],
        )
        result = WorkspaceInventoryCollector(auth=mock_auth)._list_all_workspaces()
        assert result == ["ws-1", "ws-2"]

    def test_retorna_lista_vazia_sem_workspaces_validos(self, mock_auth, mocker):
        mocker.patch.object(
            WorkspaceInventoryCollector,
            "_paginate",
            return_value=[
                {"id": "pg-1", "type": "PersonalGroup"},
                {"id": "pg-2", "type": "AdminWorkspace"},
            ],
        )
        result = WorkspaceInventoryCollector(auth=mock_auth)._list_all_workspaces()
        assert result == []

    def test_retorna_todos_os_workspaces_validos(self, mock_auth, mocker):
        mocker.patch.object(
            WorkspaceInventoryCollector,
            "_paginate",
            return_value=[
                {"id": "ws-1", "type": "Workspace"},
                {"id": "ws-2", "type": "Workspace"},
            ],
        )
        result = WorkspaceInventoryCollector(auth=mock_auth)._list_all_workspaces()
        assert result == ["ws-1", "ws-2"]


# ── _extract_artifact_users ───────────────────────────────────────────────────

class TestExtractArtifactUsers:
    def test_normaliza_access_right_de_report(self, collector):
        workspaces_raw = [
            {
                "id": "ws-1",
                "name": "WS",
                "reports": [
                    {
                        "id": "rpt-1",
                        "name": "Meu Report",
                        "users": [
                            {
                                "emailAddress": "user@test.com",
                                "displayName": "User",
                                "identifier": "user@test.com",
                                "principalType": "User",
                                "reportUserAccessRight": "Owner",
                                "graphId": "graph-1",
                            }
                        ],
                    }
                ],
            }
        ]
        result = collector._extract_artifact_users(workspaces_raw)
        assert len(result) == 1
        row = result[0]
        assert row["accessRight"] == "Owner"
        assert row["artifact_type"] == "reports"
        assert row["artifact_id"] == "rpt-1"
        assert row["workspace_id"] == "ws-1"
        assert row["emailAddress"] == "user@test.com"

    def test_normaliza_access_right_de_dataset(self, collector):
        workspaces_raw = [
            {
                "id": "ws-1",
                "name": "WS",
                "datasets": [
                    {
                        "id": "ds-1",
                        "name": "DS",
                        "users": [{"emailAddress": "a@x.com", "datasetUserAccessRight": "ReadWrite"}],
                    }
                ],
            }
        ]
        result = collector._extract_artifact_users(workspaces_raw)
        assert len(result) == 1
        assert result[0]["accessRight"] == "ReadWrite"
        assert result[0]["artifact_type"] == "datasets"

    def test_ignora_artefatos_sem_usuarios(self, collector):
        workspaces_raw = [
            {
                "id": "ws-1",
                "name": "WS",
                "reports": [{"id": "rpt-1", "name": "R", "users": []}],
            }
        ]
        result = collector._extract_artifact_users(workspaces_raw)
        assert result == []

    def test_multiplos_tipos_de_artefatos(self, collector):
        workspaces_raw = [
            {
                "id": "ws-1",
                "name": "WS",
                "reports": [
                    {"id": "r1", "name": "R", "users": [{"emailAddress": "a@x.com", "reportUserAccessRight": "Viewer"}]}
                ],
                "datasets": [
                    {"id": "d1", "name": "D", "users": [{"emailAddress": "b@x.com", "datasetUserAccessRight": "ReadWrite"}]}
                ],
                "Lakehouse": [
                    {"id": "lh1", "name": "LH", "users": [{"emailAddress": "c@x.com", "LakehouseUserAccessRight": "Admin"}]}
                ],
            }
        ]
        result = collector._extract_artifact_users(workspaces_raw)
        assert len(result) == 3
        types = {r["artifact_type"] for r in result}
        assert types == {"reports", "datasets", "Lakehouse"}

    def test_retorna_vazio_sem_workspaces(self, collector):
        assert collector._extract_artifact_users([]) == []


# ── _extract_datasources ──────────────────────────────────────────────────────

class TestExtractDatasources:
    def test_extrai_datasource_como_dict(self, collector):
        workspaces_raw = [
            {
                "id": "ws-1",
                "name": "WS",
                "datasets": [
                    {
                        "id": "ds-1",
                        "name": "DS",
                        "datasourceUsages": [
                            {
                                "datasourceInstanceId": {
                                    "datasourceType": "Sql",
                                    "connectionDetails": {"server": "srv", "database": "db"},
                                    "datasourceId": "did-1",
                                    "gatewayId": "gw-1",
                                }
                            }
                        ],
                    }
                ],
            }
        ]
        result = collector._extract_datasources(workspaces_raw)
        assert len(result) == 1
        row = result[0]
        assert row["datasource_type"] == "Sql"
        assert row["datasource_id"] == "did-1"
        assert row["gateway_id"] == "gw-1"
        assert row["instance_id_raw"] is None
        assert row["workspace_id"] == "ws-1"
        assert row["dataset_id"] == "ds-1"

    def test_extrai_datasource_como_string_sem_lookup(self, collector):
        """GUID sem datasourceInstances no workspace → campos de tipo ficam None."""
        workspaces_raw = [
            {
                "id": "ws-1",
                "name": "WS",
                "datasets": [
                    {
                        "id": "ds-1",
                        "name": "DS",
                        "datasourceUsages": [{"datasourceInstanceId": "opaque-ref-123"}],
                    }
                ],
            }
        ]
        result = collector._extract_datasources(workspaces_raw)
        assert len(result) == 1
        assert result[0]["instance_id_raw"] == "opaque-ref-123"
        assert result[0]["datasource_type"] is None

    def test_resolve_datasource_via_lookup(self, collector):
        """GUID é resolvido contra self._datasource_instances (nível raiz do scan)."""
        # Simula o que _get_scan_result acumula em self._datasource_instances
        collector._datasource_instances = [
            {
                "datasourceId": "inst-guid-1",
                "datasourceType": "Sql",
                "gatewayId": "gw-1",
                "connectionDetails": {"server": "srv", "database": "db"},
            }
        ]
        workspaces_raw = [
            {
                "id": "ws-1",
                "name": "WS",
                "datasets": [
                    {
                        "id": "ds-1",
                        "name": "DS",
                        "datasourceUsages": [{"datasourceInstanceId": "inst-guid-1"}],
                    }
                ],
            }
        ]
        result = collector._extract_datasources(workspaces_raw)
        assert len(result) == 1
        row = result[0]
        assert row["datasource_type"] == "Sql"
        assert row["gateway_id"] == "gw-1"
        assert row["datasource_id"] == "inst-guid-1"
        assert row["instance_id_raw"] == "inst-guid-1"
        assert "srv" in row["connection_details"]

    def test_ignora_dataset_sem_datasource_usages(self, collector):
        workspaces_raw = [
            {"id": "ws-1", "name": "WS", "datasets": [{"id": "ds-1", "name": "DS"}]}
        ]
        result = collector._extract_datasources(workspaces_raw)
        assert result == []

    def test_retorna_vazio_sem_workspaces(self, collector):
        assert collector._extract_datasources([]) == []


# ── _extract_semantic_models ──────────────────────────────────────────────────

class TestExtractSemanticModels:
    def test_extrai_estrutura_hierarquica(self, collector):
        workspaces_raw = [
            {
                "id": "ws-1",
                "name": "WS",
                "datasets": [
                    {
                        "id": "ds-1",
                        "name": "Modelo",
                        "tables": [
                            {
                                "name": "Vendas",
                                "columns": [{"name": "id"}, {"name": "valor"}],
                                "measures": [{"name": "Total"}],
                                "isHidden": False,
                            }
                        ],
                        "relationships": [{"fromTable": "Vendas", "toTable": "Clientes"}],
                        "expressions": [{"name": "CurrentYear", "expression": "YEAR(NOW())"}],
                    }
                ],
            }
        ]
        result = collector._extract_semantic_models(workspaces_raw)
        assert len(result) == 1
        model = result[0]
        assert model["dataset_id"] == "ds-1"
        assert model["workspace_id"] == "ws-1"
        assert len(model["tables"]) == 1
        assert model["tables"][0]["name"] == "Vendas"
        assert len(model["tables"][0]["columns"]) == 2
        assert len(model["tables"][0]["measures"]) == 1
        assert len(model["relationships"]) == 1
        assert len(model["expressions"]) == 1

    def test_dataset_sem_tabelas_retorna_modelo_vazio(self, collector):
        workspaces_raw = [
            {
                "id": "ws-1",
                "name": "WS",
                "datasets": [{"id": "ds-1", "name": "DS"}],
            }
        ]
        result = collector._extract_semantic_models(workspaces_raw)
        assert len(result) == 1
        assert result[0]["tables"] == []
        assert result[0]["relationships"] == []
        assert result[0]["expressions"] == []

    def test_ignora_workspace_sem_datasets(self, collector):
        workspaces_raw = [{"id": "ws-1", "name": "WS"}]
        result = collector._extract_semantic_models(workspaces_raw)
        assert result == []

    def test_retorna_vazio_sem_workspaces(self, collector):
        assert collector._extract_semantic_models([]) == []


# ── collect() integration ─────────────────────────────────────────────────────

class TestCollect:
    def test_retorna_novas_chaves_no_resultado(self, mock_auth, mocker):
        mocker.patch.object(
            WorkspaceInventoryCollector,
            "_list_all_workspaces",
            return_value=["ws-1"],
        )
        mocker.patch.object(
            WorkspaceInventoryCollector,
            "_scan_workspaces",
            return_value=[
                {
                    "id": "ws-1",
                    "name": "WS",
                    "type": "Workspace",
                    "reports": [],
                    "datasets": [],
                }
            ],
        )
        result = WorkspaceInventoryCollector(auth=mock_auth).collect()

        assert "artifact_users" in result
        assert "datasources" in result
        assert "semantic_models" in result
        assert "total_artifact_users" in result["summary"]
        assert "total_datasources" in result["summary"]
        assert "total_semantic_models" in result["summary"]

    def test_contadores_corretos_no_summary(self, mock_auth, mocker):
        mocker.patch.object(
            WorkspaceInventoryCollector,
            "_list_all_workspaces",
            return_value=["ws-1"],
        )
        mocker.patch.object(
            WorkspaceInventoryCollector,
            "_scan_workspaces",
            return_value=[
                {
                    "id": "ws-1",
                    "name": "WS",
                    "type": "Workspace",
                    "reports": [
                        {
                            "id": "r1",
                            "name": "R",
                            "users": [{"emailAddress": "u@x.com", "reportUserAccessRight": "Viewer"}],
                        }
                    ],
                    "datasets": [
                        {
                            "id": "d1",
                            "name": "D",
                            "datasourceUsages": [{"datasourceInstanceId": "ref-1"}],
                            "tables": [{"name": "T", "columns": [], "measures": []}],
                            "users": [],
                        }
                    ],
                }
            ],
        )
        result = WorkspaceInventoryCollector(auth=mock_auth).collect()

        assert result["summary"]["total_artifact_users"] == 1
        assert result["summary"]["total_datasources"] == 1
        assert result["summary"]["total_semantic_models"] == 1

    def test_retorna_estrutura_vazia_sem_workspaces(self, mock_auth, mocker):
        mocker.patch.object(
            WorkspaceInventoryCollector,
            "_list_all_workspaces",
            return_value=[],
        )
        result = WorkspaceInventoryCollector(auth=mock_auth).collect()

        assert result["workspaces"] == []
        assert result["artifact_users"] == []
        assert result["datasources"] == []
        assert result["semantic_models"] == []
        assert result["summary"]["total_workspaces"] == 0
        assert result["summary"]["total_artifact_users"] == 0
