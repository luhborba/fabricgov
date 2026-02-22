from typing import Any, Callable
from pathlib import Path
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector
from fabricgov.checkpoint import Checkpoint
from fabricgov.exceptions import TooManyRequestsError, CheckpointSavedException


class DatasetAccessCollector(BaseCollector):
    """
    Coleta permissões de acesso em datasets via API Admin com suporte a checkpoint.
    
    Para cada dataset encontrado no inventory, faz:
    GET /v1.0/myorg/admin/datasets/{datasetId}/users
    
    API: https://learn.microsoft.com/rest/api/power-bi/admin/datasets-get-dataset-users-as-admin
    
    Estratégia de rate limit:
    - Ao detectar 429, pausa e salva checkpoint
    - Retoma de onde parou em próxima execução
    
    Uso com checkpoint (recomendado para ambientes grandes):
        collector = DatasetAccessCollector(
            auth=auth,
            inventory_result=inventory_result,
            checkpoint_file="output/checkpoint_dataset_access.json"
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
        **kwargs
    ):
        """
        Args:
            auth: Provedor de autenticação
            inventory_result: Resultado do WorkspaceInventoryCollector
            progress_callback: Função chamada a cada update de progresso
            checkpoint_file: Caminho do checkpoint (habilita modo incremental)
        """
        super().__init__(
            auth=auth,
            base_url="https://api.powerbi.com",
            **kwargs
        )
        self._inventory_result = inventory_result
        self._progress = progress_callback or (lambda msg: None)
        self._checkpoint = Checkpoint(checkpoint_file) if checkpoint_file else None

    def collect(self) -> dict[str, Any]:
        """
        Coleta permissões de acesso em datasets.
        
        Returns:
            Resultado completo ou parcial (se retomando de checkpoint)
            
        Raises:
            CheckpointSavedException: Quando rate limit interrompe coleta e salva checkpoint
        """
        datasets = self._inventory_result.get("datasets", [])
        
        # Filtra datasets de Personal Workspaces
        filtered_datasets = [
            ds for ds in datasets
            if not (ds.get("workspace_name") or "").startswith("PersonalWorkspace")
        ]
        
        # Carrega checkpoint se existir
        processed_ids = set()
        dataset_access = []
        errors = []
        
        if self._checkpoint and self._checkpoint.exists():
            checkpoint_data = self._checkpoint.load()
            processed_ids = set(checkpoint_data.get("processed_ids", []))
            partial_data = checkpoint_data.get("partial_data", {})
            dataset_access = partial_data.get("dataset_access", [])
            errors = partial_data.get("dataset_access_errors", [])
            
            self._progress(f"♻️  Checkpoint detectado: {checkpoint_data['progress']}")
            self._progress(f"   Retomando coleta...")
        
        # Filtra datasets já processados
        datasets_to_process = [
            ds for ds in filtered_datasets
            if ds.get("id") not in processed_ids
        ]
        
        skipped_personal = len(datasets) - len(filtered_datasets)
        already_processed = len(processed_ids)
        to_process = len(datasets_to_process)
        total_expected = len(filtered_datasets)
        
        self._progress(f"Total de datasets: {len(datasets)}")
        self._progress(f"Datasets em Personal Workspaces ignorados: {skipped_personal}")
        if already_processed > 0:
            self._progress(f"Já processados (checkpoint): {already_processed}")
        self._progress(f"A processar nesta execução: {to_process}")
        
        if to_process == 0:
            self._progress("✓ Todos os datasets já foram processados!")
            return self._build_result(
                dataset_access, errors, len(datasets),
                skipped_personal, total_expected, 0
            )
        
        # Coleta acessos
        users_set = set()
        service_principals_set = set()
        permissions_counter = {}
        datasets_with_users = 0
        
        for idx, dataset in enumerate(datasets_to_process, start=1):
            dataset_id = dataset.get("id")
            dataset_name = dataset.get("name")
            workspace_id = dataset.get("workspace_id")
            workspace_name = dataset.get("workspace_name")
            
            if idx % 100 == 0:
                self._progress(f"Processando dataset {idx}/{to_process}...")
            
            try:
                # GET users do dataset
                response = self._get(
                    endpoint=f"/v1.0/myorg/admin/datasets/{dataset_id}/users",
                    scope=self.POWERBI_SCOPE,
                )
                
                users = response.get("value", [])
                
                if users:
                    datasets_with_users += 1
                
                for user in users:
                    email = user.get("emailAddress")
                    identifier = user.get("identifier")
                    principal_type = user.get("principalType", "User")
                    permission = user.get("datasetUserAccessRight", "Unknown")
                    
                    dataset_access.append({
                        "dataset_id": dataset_id,
                        "dataset_name": dataset_name,
                        "workspace_id": workspace_id,
                        "workspace_name": workspace_name,
                        "user_email": email,
                        "user_identifier": identifier,
                        "principal_type": principal_type,
                        "permission": permission,
                    })
                    
                    if principal_type == "User":
                        users_set.add(identifier)
                    elif principal_type == "App":
                        service_principals_set.add(identifier)
                    
                    permissions_counter[permission] = permissions_counter.get(permission, 0) + 1
                
                processed_ids.add(dataset_id)
                
                # Salva checkpoint a cada 100 datasets
                if self._checkpoint and len(processed_ids) % 100 == 0:
                    self._save_checkpoint(
                        processed_ids, dataset_access, errors,
                        already_processed + idx, total_expected
                    )
            
            except TooManyRequestsError as e:
                # Rate limit - salva checkpoint e interrompe
                self._progress(f"⚠️  Rate limit atingido no dataset {idx}")
                self._save_checkpoint(
                    processed_ids, dataset_access, errors,
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
                    "dataset_id": dataset_id,
                    "dataset_name": dataset_name,
                    "workspace_id": workspace_id,
                    "workspace_name": workspace_name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                })
                if hasattr(e, 'status_code'):
                    errors[-1]["status_code"] = e.status_code
                if hasattr(e, 'response_body'):
                    errors[-1]["response_body"] = e.response_body[:200]
                
                processed_ids.add(dataset_id)
                continue
        
        # Coleta completa - remove checkpoint
        if self._checkpoint:
            self._checkpoint.clear()
            self._progress("🗑️  Checkpoint removido (coleta completa)")
        
        self._progress(f"✓ Coleta concluída: {len(dataset_access)} acessos coletados")
        if errors:
            self._progress(f"⚠️  {len(errors)} datasets com erro")
        
        return self._build_result(
            dataset_access, errors, len(datasets),
            skipped_personal, total_expected, datasets_with_users
        )
    
    def _save_checkpoint(
        self,
        processed_ids: set[str],
        dataset_access: list[dict],
        errors: list[dict],
        current: int,
        total: int
    ) -> None:
        """Salva checkpoint no disco."""
        self._checkpoint.save(
            processed_ids=processed_ids,
            partial_data={
                "dataset_access": dataset_access,
                "dataset_access_errors": errors,
            },
            progress=f"{current}/{total}"
        )
        self._progress(f"💾 Checkpoint salvo: {current}/{total}")
    
    def _build_result(
        self,
        dataset_access: list[dict],
        errors: list[dict],
        total_datasets: int,
        skipped_personal: int,
        datasets_processed: int,
        datasets_with_users: int
    ) -> dict[str, Any]:
        """Monta resultado final."""
        users_set = set()
        service_principals_set = set()
        permissions_counter = {}
        
        for access in dataset_access:
            identifier = access.get("user_identifier")
            principal_type = access.get("principal_type")
            permission = access.get("permission")
            
            if principal_type == "User":
                users_set.add(identifier)
            elif principal_type == "App":
                service_principals_set.add(identifier)
            
            permissions_counter[permission] = permissions_counter.get(permission, 0) + 1
        
        return {
            "dataset_access": dataset_access,
            "dataset_access_errors": errors,
            "summary": {
                "total_datasets": total_datasets,
                "personal_workspaces_datasets_skipped": skipped_personal,
                "datasets_processed": datasets_processed,
                "datasets_with_users": datasets_with_users,
                "total_access_entries": len(dataset_access),
                "users_count": len(users_set),
                "service_principals_count": len(service_principals_set),
                "permissions_breakdown": permissions_counter,
                "errors_count": len(errors),
            }
        }