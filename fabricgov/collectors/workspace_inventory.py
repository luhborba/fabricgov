from typing import Callable, Any
import time
from datetime import datetime
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector


class WorkspaceInventoryCollector(BaseCollector):
    """
    Coleta inventário completo de workspaces via Admin Scan API.
    
    Fluxo:
    1. Lista todos os workspaces via GET /admin/groups
    2. Divide em lotes de 100 (limite da API)
    3. Para cada lote: POST scan → polling status → GET result
    4. Agrega todos os resultados
    
    Uso:
        collector = WorkspaceInventoryCollector(
            auth=auth,
            progress_callback=lambda msg: print(msg)
        )
        result = collector.collect()
    """

    FABRIC_SCOPE = "https://analysis.windows.net/powerbi/api/.default"
    BATCH_SIZE = 100

    def __init__(
        self,
        auth: AuthProvider,
        progress_callback: Callable[[str], None] | None = None,
        poll_interval: int = 5,
        max_poll_time: int = 600,
        **kwargs
    ):
        """
        Args:
            auth: Provedor de autenticação
            progress_callback: função(msg: str) chamada a cada update de progresso
            poll_interval: segundos entre verificações de status do scan
            max_poll_time: timeout máximo em segundos por scan
        """
        super().__init__(
            auth=auth,
            base_url="https://api.powerbi.com",
            **kwargs
        )
        self._progress = progress_callback or (lambda msg: None)
        self._poll_interval = poll_interval
        self._max_poll_time = max_poll_time
        
        # Acumuladores de datasources (preenchidos durante os scans)
        self._datasource_instances = []
        self._misconfigured_datasource_instances = []

    def collect(self) -> dict[str, Any]:
        """
        Executa coleta completa do inventário de workspaces e artefatos.
        
        Returns:
            {
                "workspaces": [...],  # metadados dos workspaces
                "dashboards": [...],
                "datasets": [...],
                "reports": [...],
                ... (todos os tipos de artefatos)
                "datasourceInstances": [...],
                "misconfiguredDatasourceInstances": [...],
                "summary": {
                    "total_workspaces": int,
                    "total_items": int,
                    "items_by_type": {...},
                    "scan_duration_seconds": float,
                    "batches_processed": int,
                }
            }
        """
        start_time = time.time()
        
        # Etapa 1: Lista todos os workspaces
        self._progress("Listando workspaces do tenant...")
        workspace_ids = self._list_all_workspaces()
        self._progress(f"Encontrados {len(workspace_ids)} workspaces")

        if not workspace_ids:
            return self._empty_result()

        # Etapa 2: Divide em lotes de 100
        batches = [
            workspace_ids[i:i + self.BATCH_SIZE]
            for i in range(0, len(workspace_ids), self.BATCH_SIZE)
        ]
        total_batches = len(batches)
        self._progress(f"Dividido em {total_batches} lote(s) de até {self.BATCH_SIZE} workspaces")

        # Etapa 3: Processa cada lote
        all_workspaces_raw = []
        for batch_num, batch_ids in enumerate(batches, start=1):
            self._progress(f"\n--- Lote {batch_num}/{total_batches} ({len(batch_ids)} workspaces) ---")
            batch_result = self._scan_workspaces(batch_ids, batch_num, total_batches)
            all_workspaces_raw.extend(batch_result)

        # Etapa 4: Extrai e agrupa artefatos por tipo
        self._progress("\nExtraindo e agrupando artefatos...")
        
        # Inicializa acumuladores de datasources
        self._datasource_instances = []
        self._misconfigured_datasource_instances = []
        
        result = self._extract_artifacts(all_workspaces_raw)
        
        # Adiciona datasources ao resultado
        result["datasourceInstances"] = self._datasource_instances
        result["misconfiguredDatasourceInstances"] = self._misconfigured_datasource_instances
        result["summary"]["items_by_type"]["datasourceInstances"] = len(self._datasource_instances)
        result["summary"]["items_by_type"]["misconfiguredDatasourceInstances"] = len(
            self._misconfigured_datasource_instances
        )
        
        # Etapa 5: Calcula summary
        duration = time.time() - start_time
        result["summary"]["total_workspaces"] = len(result["workspaces"])
        result["summary"]["total_items"] = sum(result["summary"]["items_by_type"].values())
        result["summary"]["scan_duration_seconds"] = round(duration, 2)
        result["summary"]["batches_processed"] = total_batches

        total_items = result["summary"]["total_items"]
        self._progress(
            f"\n✓ Coleta concluída: {len(result['workspaces'])} workspaces, "
            f"{total_items} itens em {duration:.1f}s"
        )

        return result

    # ── métodos internos ──────────────────────────────────────────────────

    def _list_all_workspaces(self) -> list[str]:
        """
        Lista todos os workspace IDs via GET /admin/groups.
        Usa paginação automática via _paginate do BaseCollector.
        
        Returns:
            Lista de workspace IDs (GUIDs)
        """
        workspaces = self._paginate(
            endpoint="/v1.0/myorg/admin/groups",
            scope=self.FABRIC_SCOPE,
            params={"$top": 5000}  # máximo por página
        )
        return [ws["id"] for ws in workspaces]

    def _scan_workspaces(
        self,
        workspace_ids: list[str],
        batch_num: int,
        total_batches: int
    ) -> list[dict[str, Any]]:
        """
        Executa scan assíncrono de um lote de workspaces.
        
        Args:
            workspace_ids: lista de até 100 workspace IDs
            batch_num: número do lote atual (para logging)
            total_batches: total de lotes (para logging)
        
        Returns:
            Lista de workspaces com metadados completos
        """
        # POST /workspaces/getInfo - inicia scan
        self._progress(f"Iniciando scan do lote {batch_num}/{total_batches}...")
        scan_response = self._post_scan(workspace_ids)
        scan_id = scan_response["id"]
        self._progress(f"Scan iniciado (id: {scan_id})")

        # Polling até scan completar
        self._wait_for_scan(scan_id, batch_num, total_batches)

        # GET /scanResult/{scanId} - coleta resultado
        self._progress(f"Coletando resultado do scan {scan_id}...")
        result = self._get_scan_result(scan_id)
        
        workspaces = result.get("workspaces", [])
        self._progress(f"✓ Lote {batch_num}/{total_batches} concluído: {len(workspaces)} workspaces")
        
        return workspaces

    def _post_scan(self, workspace_ids: list[str]) -> dict[str, Any]:
        """
        POST /v1.0/myorg/admin/workspaces/getInfo
        Inicia scan assíncrono e retorna scan_id.
        """
        url = f"{self._base_url}/v1.0/myorg/admin/workspaces/getInfo"
        token = self._auth.get_token(self.FABRIC_SCOPE)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        payload = {
            "workspaces": workspace_ids,
            "datasetExpressions": True,
            "datasetSchema": True,
            "datasourceDetails": True,
            "getArtifactUsers": True,
            "lineage": True,
        }
        
        response = self._client.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()

    def _wait_for_scan(self, scan_id: str, batch_num: int, total_batches: int) -> None:
        """
        Polling em GET /scanStatus/{scanId} até status = Succeeded.
        
        Raises:
            TimeoutError: se exceder max_poll_time
            RuntimeError: se scan falhar
        """
        elapsed = 0
        while elapsed < self._max_poll_time:
            time.sleep(self._poll_interval)
            elapsed += self._poll_interval

            status_response = self._get(
                endpoint=f"/v1.0/myorg/admin/workspaces/scanStatus/{scan_id}",
                scope=self.FABRIC_SCOPE,
            )
            status = status_response.get("status")
            
            self._progress(f"Lote {batch_num}/{total_batches} - Status: {status} ({elapsed}s)")

            if status == "Succeeded":
                return
            elif status == "Failed":
                error = status_response.get("error", "Unknown error")
                raise RuntimeError(f"Scan {scan_id} falhou: {error}")

        raise TimeoutError(f"Scan {scan_id} excedeu timeout de {self._max_poll_time}s")

    def _get_scan_result(self, scan_id: str) -> dict[str, Any]:
        """
        GET /v1.0/myorg/admin/workspaces/scanResult/{scanId}
        Retorna resultado completo do scan incluindo datasources.
        """
        result = self._get(
            endpoint=f"/v1.0/myorg/admin/workspaces/scanResult/{scan_id}",
            scope=self.FABRIC_SCOPE,
        )
        
        # Acumula datasources de todos os scans
        self._datasource_instances.extend(result.get("datasourceInstances", []))
        self._misconfigured_datasource_instances.extend(
            result.get("misconfiguredDatasourceInstances", [])
        )
        
        return result

    def _extract_artifacts(self, workspaces_raw: list[dict]) -> dict[str, Any]:
        """
        Extrai artefatos de dentro dos workspaces e cria seções separadas.
        
        Args:
            workspaces_raw: lista de workspaces como retornados pelo scan
        
        Returns:
            Dicionário com workspaces (só metadados) e artefatos agrupados por tipo
        """
        # Lista completa de tipos de artefatos conhecidos
        artifact_types = [
            "dashboards",
            "datasets",
            "reports",
            "dataflows",
            "datamarts",
            "workbooks",
            "Lakehouse",
            "warehouses",
            "Notebook",
            "sparkJobDefinitions",
            "mlModels",
            "mlExperiments",
            "SQLDatabase",
            "KQLDashboard",
            "kqlDatabases",
            "kqlQuerysets",
            "eventstreams",
            "reflex",
            "semanticModels",
            "SQLAnalyticsEndpoint",
            "MirroredAzureDatabricksCatalog",
            "MirroredDatabase",
            "mirroredWarehouses",
            "graphqlApis",
            "sqlDatabases",
            "variableLibraries",
            "paginatedReports",
            "deploymentPipelines",
            "DataPipeline",
            "Environment",
            "Exploration",
            "DataAgent",
            "OrgApp",
            
        ]

        # Inicializa estrutura de output
        output = {
            "workspaces": [],
            "summary": {"items_by_type": {}}
        }
        
        # Adiciona seção vazia para cada tipo de artefato
        for artifact_type in artifact_types:
            output[artifact_type] = []
            output["summary"]["items_by_type"][artifact_type] = 0

        # Processa cada workspace
        for ws in workspaces_raw:
            # Extrai metadados do workspace (sem artefatos)
            ws_metadata = {
                "id": ws.get("id"),
                "name": ws.get("name"),
                "description": ws.get("description"),
                "type": ws.get("type"),
                "state": ws.get("state"),
                "isReadOnly": ws.get("isReadOnly"),
                "isOrphaned": ws.get("isOrphaned"),
                "isOnDedicatedCapacity": ws.get("isOnDedicatedCapacity"),
                "capacityId": ws.get("capacityId"),
                "defaultDatasetStorageFormat": ws.get("defaultDatasetStorageFormat"),
            }
            output["workspaces"].append(ws_metadata)

            # Extrai artefatos de cada tipo
            for artifact_type in artifact_types:
                artifacts = ws.get(artifact_type, [])
                for artifact in artifacts:
                    # Adiciona contexto do workspace em cada artefato
                    artifact_with_context = {
                        **artifact,
                        "workspace_id": ws.get("id"),
                        "workspace_name": ws.get("name"),
                    }
                    output[artifact_type].append(artifact_with_context)

        # Calcula contadores por tipo
        for artifact_type in artifact_types:
            count = len(output[artifact_type])
            output["summary"]["items_by_type"][artifact_type] = count

        return output

    def _empty_result(self) -> dict[str, Any]:
        """Retorna estrutura vazia quando não há workspaces."""
        artifact_types = [
            "dashboards", "datasets", "reports", "dataflows", "datamarts",
            "workbooks", "Lakehouse", "warehouses", "Notebook", "sparkJobDefinitions",
            "mlModels", "mlExperiments","KQLDashboard", "kqlDatabases", "kqlQuerysets", "eventstreams",
            "reflex", "semanticModels", "sqlEndpoints", "MirroredDatabase",
            "mirroredWarehouses", "graphqlApis", "sqlDatabases", "variableLibraries",
            "paginatedReports", "deploymentPipelines","MirroredAzureDatabricksCatalog","DataPipeline",
            "SQLDatabase","SQLAnalyticsEndpoint","Environment","DataAgent","Exploration","OrgApp",
        ]
        
        empty = {
            "workspaces": [],
            "datasourceInstances": [],
            "misconfiguredDatasourceInstances": [],
            "summary": {
                "total_workspaces": 0,
                "total_items": 0,
                "items_by_type": {},
                "scan_duration_seconds": 0,
                "batches_processed": 0,
            }
        }
        
        for artifact_type in artifact_types:
            empty[artifact_type] = []
            empty["summary"]["items_by_type"][artifact_type] = 0
        
        empty["summary"]["items_by_type"]["datasourceInstances"] = 0
        empty["summary"]["items_by_type"]["misconfiguredDatasourceInstances"] = 0
        
        return empty