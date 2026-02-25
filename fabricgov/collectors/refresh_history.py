from typing import Any, Callable
from pathlib import Path
from datetime import datetime
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector
from fabricgov.checkpoint import Checkpoint
from fabricgov.exceptions import TooManyRequestsError, CheckpointSavedException


class RefreshHistoryCollector(BaseCollector):
    """
    Coleta histórico de refreshes de datasets e dataflows via API Admin.
    
    Para cada dataset/dataflow encontrado no inventory, faz:
    - Datasets: GET /v1.0/myorg/admin/datasets/{datasetId}/refreshes?$top={limit}
    - Dataflows: GET /v1.0/myorg/admin/dataflows/{dataflowId}/transactions?$top={limit}
    
    APIs:
    - https://learn.microsoft.com/rest/api/power-bi/admin/datasets-get-refreshes-in-group-as-admin
    - https://learn.microsoft.com/rest/api/power-bi/admin/dataflows-get-dataflow-transactions-as-admin
    
    Uso com checkpoint (recomendado para ambientes grandes):
        collector = RefreshHistoryCollector(
            auth=auth,
            inventory_result=inventory_result,
            checkpoint_file="output/checkpoint_refresh_history.json",
            history_limit=100  # últimos 100 refreshes por artefato
        )
        
        try:
            result = collector.collect()
        except CheckpointSavedException as e:
            print(f"⏹️  {e.progress} - Execute novamente após 1 hora")
    """

    POWERBI_SCOPE = "https://analysis.windows.net/powerbi/api/.default"

    def __init__(
        self,
        auth: AuthProvider,
        inventory_result: dict[str, Any],
        progress_callback: Callable[[str], None] | None = None,
        checkpoint_file: str | Path | None = None,
        history_limit: int = 100,
        **kwargs
    ):
        """
        Args:
            auth: Provedor de autenticação
            inventory_result: Resultado do WorkspaceInventoryCollector
            progress_callback: Função chamada a cada update de progresso
            checkpoint_file: Caminho do checkpoint (habilita modo incremental)
            history_limit: Número máximo de refreshes a coletar por artefato (padrão: 100)
        """
        super().__init__(
            auth=auth,
            base_url="https://api.powerbi.com",
            **kwargs
        )
        self._inventory_result = inventory_result
        self._progress = progress_callback or (lambda msg: None)
        self._checkpoint = Checkpoint(checkpoint_file) if checkpoint_file else None
        self._history_limit = history_limit

    def collect(self) -> dict[str, Any]:
        """
        Coleta histórico de refreshes de datasets e dataflows.
        
        Returns:
            Resultado completo ou parcial (se retomando de checkpoint)
            
        Raises:
            CheckpointSavedException: Quando rate limit interrompe coleta e salva checkpoint
        """
        datasets = self._inventory_result.get("datasets", [])
        dataflows = self._inventory_result.get("dataflows", [])
        
        # Filtra Personal Workspaces
        filtered_datasets = [
            ds for ds in datasets
            if not (ds.get("workspace_name") or "").startswith("PersonalWorkspace")
        ]
        
        filtered_dataflows = [
            df for df in dataflows
            if not (df.get("workspace_name") or "").startswith("PersonalWorkspace")
        ]
        
        # Carrega checkpoint se existir
        processed_ids = set()
        refresh_history = []
        errors = []
        
        if self._checkpoint and self._checkpoint.exists():
            checkpoint_data = self._checkpoint.load()
            processed_ids = set(checkpoint_data.get("processed_ids", []))
            partial_data = checkpoint_data.get("partial_data", {})
            refresh_history = partial_data.get("refresh_history", [])
            errors = partial_data.get("refresh_history_errors", [])
            
            self._progress(f"♻️  Checkpoint detectado: {checkpoint_data['progress']}")
            self._progress(f"   Retomando coleta...")
        
        # Prepara lista de artefatos a processar
        artifacts_to_process = []
        
        for ds in filtered_datasets:
            if ds.get("id") not in processed_ids:
                artifacts_to_process.append({
                    "type": "Dataset",
                    "id": ds.get("id"),
                    "name": ds.get("name"),
                    "workspace_id": ds.get("workspace_id"),
                    "workspace_name": ds.get("workspace_name"),
                })
        
        for df in filtered_dataflows:
            if df.get("objectId") not in processed_ids:
                artifacts_to_process.append({
                    "type": "Dataflow",
                    "id": df.get("objectId"),
                    "name": df.get("name"),
                    "workspace_id": df.get("workspace_id"),
                    "workspace_name": df.get("workspace_name"),
                })
        
        skipped_datasets = len(datasets) - len(filtered_datasets)
        skipped_dataflows = len(dataflows) - len(filtered_dataflows)
        already_processed = len(processed_ids)
        to_process = len(artifacts_to_process)
        total_expected = len(filtered_datasets) + len(filtered_dataflows)
        
        self._progress(f"Total de datasets: {len(datasets)} ({skipped_datasets} em Personal Workspaces ignorados)")
        self._progress(f"Total de dataflows: {len(dataflows)} ({skipped_dataflows} em Personal Workspaces ignorados)")
        if already_processed > 0:
            self._progress(f"Já processados (checkpoint): {already_processed}")
        self._progress(f"A processar nesta execução: {to_process}")
        
        if to_process == 0:
            self._progress("✓ Todos os artefatos já foram processados!")
            return self._build_result(refresh_history, errors, total_expected, already_processed)
        
        # Coleta histórico
        for idx, artifact in enumerate(artifacts_to_process, start=1):
            artifact_type = artifact["type"]
            artifact_id = artifact["id"]
            artifact_name = artifact["name"]
            workspace_id = artifact["workspace_id"]
            workspace_name = artifact["workspace_name"]
            
            if idx % 50 == 0:
                self._progress(f"Processando artefato {idx}/{to_process}...")
            
            try:
                # Coleta histórico de refresh
                if artifact_type == "Dataset":
                    history = self._get_dataset_refresh_history(artifact_id)
                elif artifact_type == "Dataflow":
                    history = self._get_dataflow_refresh_history(artifact_id)
                else:
                    continue
                
                # Adiciona contexto a cada refresh
                for refresh in history:
                    refresh_history.append({
                        "artifact_type": artifact_type,
                        "artifact_id": artifact_id,
                        "artifact_name": artifact_name,
                        "workspace_id": workspace_id,
                        "workspace_name": workspace_name,
                        **refresh
                    })
                
                processed_ids.add(artifact_id)
                
                # Salva checkpoint a cada 50 artefatos
                if self._checkpoint and len(processed_ids) % 50 == 0:
                    self._save_checkpoint(
                        processed_ids, refresh_history, errors,
                        already_processed + idx, total_expected
                    )
            
            except TooManyRequestsError as e:
                # Rate limit - salva checkpoint e interrompe
                self._progress(f"⚠️  Rate limit atingido no artefato {idx}")
                self._save_checkpoint(
                    processed_ids, refresh_history, errors,
                    len(processed_ids), total_expected
                )
                
                raise CheckpointSavedException(
                    checkpoint_file=str(self._checkpoint.checkpoint_file),
                    progress=f"{len(processed_ids)}/{total_expected}",
                    processed_count=len(processed_ids),
                    total_count=total_expected,
                )
            
            except Exception as e:
                # Outros erros - registra e continua
                errors.append({
                    "artifact_type": artifact_type,
                    "artifact_id": artifact_id,
                    "artifact_name": artifact_name,
                    "workspace_id": workspace_id,
                    "workspace_name": workspace_name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                })
                if hasattr(e, 'status_code'):
                    errors[-1]["status_code"] = e.status_code
                if hasattr(e, 'response_body'):
                    errors[-1]["response_body"] = e.response_body[:200]
                
                processed_ids.add(artifact_id)
                continue
        
        # Coleta completa - remove checkpoint
        if self._checkpoint:
            self._checkpoint.clear()
            self._progress("🗑️  Checkpoint removido (coleta completa)")
        
        self._progress(f"✓ Coleta concluída: {len(refresh_history)} refreshes coletados")
        if errors:
            self._progress(f"⚠️  {len(errors)} artefatos com erro")
        
        return self._build_result(refresh_history, errors, total_expected, len(processed_ids))
    
    def _get_dataset_refresh_history(self, dataset_id: str) -> list[dict]:
        """
        GET /v1.0/myorg/admin/datasets/{datasetId}/refreshes
        
        Returns:
            Lista de refreshes do dataset
        """
        response = self._get(
            endpoint=f"/v1.0/myorg/admin/datasets/{dataset_id}/refreshes",
            scope=self.POWERBI_SCOPE,
            params={"$top": self._history_limit}
        )
        
        refreshes = response.get("value", [])
        
        # Normaliza campos
        normalized = []
        for refresh in refreshes:
            # Calcula duração se tiver start e end
            start_time = refresh.get("startTime")
            end_time = refresh.get("endTime")
            duration_seconds = None
            
            if start_time and end_time:
                try:
                    start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                    end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
                    duration_seconds = int((end_dt - start_dt).total_seconds())
                except Exception:
                    pass
            
            normalized.append({
                "refresh_type": refresh.get("refreshType"),
                "start_time": start_time,
                "end_time": end_time,
                "status": refresh.get("status"),
                "duration_seconds": duration_seconds,
                "request_id": refresh.get("requestId"),
                "service_exception_json": refresh.get("serviceExceptionJson"),
            })
        
        return normalized
    
    def _get_dataflow_refresh_history(self, dataflow_id: str) -> list[dict]:
        """
        GET /v1.0/myorg/admin/dataflows/{dataflowId}/transactions
        
        Returns:
            Lista de transactions (refreshes) do dataflow
        """
        response = self._get(
            endpoint=f"/v1.0/myorg/admin/dataflows/{dataflow_id}/transactions",
            scope=self.POWERBI_SCOPE,
            params={"$top": self._history_limit}
        )
        
        transactions = response.get("value", [])
        
        # Normaliza campos
        normalized = []
        for tx in transactions:
            # Calcula duração se tiver start e end
            start_time = tx.get("startTime")
            end_time = tx.get("endTime")
            duration_seconds = None
            
            if start_time and end_time:
                try:
                    start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                    end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
                    duration_seconds = int((end_dt - start_dt).total_seconds())
                except Exception:
                    pass
            
            normalized.append({
                "refresh_type": tx.get("refreshType"),
                "start_time": start_time,
                "end_time": end_time,
                "status": tx.get("status"),
                "duration_seconds": duration_seconds,
                "request_id": tx.get("id"),
                "service_exception_json": tx.get("error"),
            })
        
        return normalized
    
    def _save_checkpoint(
        self,
        processed_ids: set[str],
        refresh_history: list[dict],
        errors: list[dict],
        current: int,
        total: int
    ) -> None:
        """Salva checkpoint no disco."""
        self._checkpoint.save(
            processed_ids=processed_ids,
            partial_data={
                "refresh_history": refresh_history,
                "refresh_history_errors": errors,
            },
            progress=f"{current}/{total}"
        )
        self._progress(f"💾 Checkpoint salvo: {current}/{total}")
    
    def _build_result(
        self,
        refresh_history: list[dict],
        errors: list[dict],
        total_artifacts: int,
        artifacts_processed: int
    ) -> dict[str, Any]:
        """Monta resultado final."""
        # Estatísticas
        total_refreshes = len(refresh_history)
        by_artifact_type = {}
        by_status = {}
        total_duration = 0
        
        for refresh in refresh_history:
            artifact_type = refresh.get("artifact_type")
            status = refresh.get("status")
            duration = refresh.get("duration_seconds") or 0
            
            by_artifact_type[artifact_type] = by_artifact_type.get(artifact_type, 0) + 1
            by_status[status] = by_status.get(status, 0) + 1
            total_duration += duration
        
        return {
            "refresh_history": refresh_history,
            "refresh_history_errors": errors,
            "summary": {
                "total_artifacts": total_artifacts,
                "artifacts_processed": artifacts_processed,
                "total_refreshes": total_refreshes,
                "refreshes_by_artifact_type": by_artifact_type,
                "refreshes_by_status": by_status,
                "total_duration_seconds": total_duration,
                "errors_count": len(errors),
            }
        }