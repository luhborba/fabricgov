from typing import Any, Callable
from pathlib import Path
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector
from fabricgov.checkpoint import Checkpoint
from fabricgov.exceptions import TooManyRequestsError, CheckpointSavedException


class DataflowAccessCollector(BaseCollector):
    """
    Coleta permissões de acesso em dataflows via API Admin com suporte a checkpoint.
    
    Para cada dataflow encontrado no inventory, faz:
    GET /v1.0/myorg/admin/dataflows/{dataflowId}/users
    
    API: https://learn.microsoft.com/rest/api/power-bi/admin/dataflows-get-dataflow-users-as-admin
    
    Estratégia de rate limit:
    - Ao detectar 429, pausa e salva checkpoint
    - Retoma de onde parou em próxima execução
    
    Uso com checkpoint (recomendado para ambientes grandes):
        collector = DataflowAccessCollector(
            auth=auth,
            inventory_result=inventory_result,
            checkpoint_file="output/checkpoint_dataflow_access.json"
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
        Coleta permissões de acesso em dataflows.
        
        Returns:
            Resultado completo ou parcial (se retomando de checkpoint)
            
        Raises:
            CheckpointSavedException: Quando rate limit interrompe coleta e salva checkpoint
        """
        dataflows = self._inventory_result.get("dataflows", [])
        
        # Filtra dataflows de Personal Workspaces
        filtered_dataflows = [
            df for df in dataflows
            if not (df.get("workspace_name") or "").startswith("PersonalWorkspace")
        ]
        
        # Carrega checkpoint se existir
        processed_ids = set()
        dataflow_access = []
        errors = []
        
        if self._checkpoint and self._checkpoint.exists():
            checkpoint_data = self._checkpoint.load()
            processed_ids = set(checkpoint_data.get("processed_ids", []))
            partial_data = checkpoint_data.get("partial_data", {})
            dataflow_access = partial_data.get("dataflow_access", [])
            errors = partial_data.get("dataflow_access_errors", [])
            
            self._progress(f"♻️  Checkpoint detectado: {checkpoint_data['progress']}")
            self._progress(f"   Retomando coleta...")
        
        # Filtra dataflows já processados
        dataflows_to_process = [
            df for df in filtered_dataflows
            if df.get("objectId") not in processed_ids
        ]
        
        skipped_personal = len(dataflows) - len(filtered_dataflows)
        already_processed = len(processed_ids)
        to_process = len(dataflows_to_process)
        total_expected = len(filtered_dataflows)
        
        self._progress(f"Total de dataflows: {len(dataflows)}")
        self._progress(f"Dataflows em Personal Workspaces ignorados: {skipped_personal}")
        if already_processed > 0:
            self._progress(f"Já processados (checkpoint): {already_processed}")
        self._progress(f"A processar nesta execução: {to_process}")
        
        if to_process == 0:
            self._progress("✓ Todos os dataflows já foram processados!")
            return self._build_result(
                dataflow_access, errors, len(dataflows),
                skipped_personal, total_expected, 0
            )
        
        # Coleta acessos
        users_set = set()
        service_principals_set = set()
        permissions_counter = {}
        dataflows_with_users = 0
        
        for idx, dataflow in enumerate(dataflows_to_process, start=1):
            dataflow_id = dataflow.get("objectId")
            dataflow_name = dataflow.get("name")
            workspace_id = dataflow.get("workspace_id")
            workspace_name = dataflow.get("workspace_name")
            
            if idx % 100 == 0:
                self._progress(f"Processando dataflow {idx}/{to_process}...")
            
            try:
                # GET users do dataflow
                response = self._get(
                    endpoint=f"/v1.0/myorg/admin/dataflows/{dataflow_id}/users",
                    scope=self.POWERBI_SCOPE,
                )
                
                users = response.get("value", [])
                
                if users:
                    dataflows_with_users += 1
                
                for user in users:
                    email = user.get("emailAddress")
                    identifier = user.get("identifier")
                    principal_type = user.get("principalType", "User")
                    permission = user.get("dataflowUserAccessRight", "Unknown")
                    
                    dataflow_access.append({
                        "dataflow_id": dataflow_id,
                        "dataflow_name": dataflow_name,
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
                
                processed_ids.add(dataflow_id)
                
                # Salva checkpoint a cada 50 dataflows
                if self._checkpoint and len(processed_ids) % 50 == 0:
                    self._save_checkpoint(
                        processed_ids, dataflow_access, errors,
                        already_processed + idx, total_expected
                    )
            
            except TooManyRequestsError as e:
                # Rate limit - salva checkpoint e interrompe
                self._progress(f"⚠️  Rate limit atingido no dataflow {idx}")
                self._save_checkpoint(
                    processed_ids, dataflow_access, errors,
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
                    "dataflow_id": dataflow_id,
                    "dataflow_name": dataflow_name,
                    "workspace_id": workspace_id,
                    "workspace_name": workspace_name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                })
                if hasattr(e, 'status_code'):
                    errors[-1]["status_code"] = e.status_code
                if hasattr(e, 'response_body'):
                    errors[-1]["response_body"] = e.response_body[:200]
                
                processed_ids.add(dataflow_id)
                continue
        
        # Coleta completa - remove checkpoint
        if self._checkpoint:
            self._checkpoint.clear()
            self._progress("🗑️  Checkpoint removido (coleta completa)")
        
        self._progress(f"✓ Coleta concluída: {len(dataflow_access)} acessos coletados")
        if errors:
            self._progress(f"⚠️  {len(errors)} dataflows com erro")
        
        return self._build_result(
            dataflow_access, errors, len(dataflows),
            skipped_personal, total_expected, dataflows_with_users
        )
    
    def _save_checkpoint(
        self,
        processed_ids: set[str],
        dataflow_access: list[dict],
        errors: list[dict],
        current: int,
        total: int
    ) -> None:
        """Salva checkpoint no disco."""
        self._checkpoint.save(
            processed_ids=processed_ids,
            partial_data={
                "dataflow_access": dataflow_access,
                "dataflow_access_errors": errors,
            },
            progress=f"{current}/{total}"
        )
        self._progress(f"💾 Checkpoint salvo: {current}/{total}")
    
    def _build_result(
        self,
        dataflow_access: list[dict],
        errors: list[dict],
        total_dataflows: int,
        skipped_personal: int,
        dataflows_processed: int,
        dataflows_with_users: int
    ) -> dict[str, Any]:
        """Monta resultado final."""
        users_set = set()
        service_principals_set = set()
        permissions_counter = {}
        
        for access in dataflow_access:
            identifier = access.get("user_identifier")
            principal_type = access.get("principal_type")
            permission = access.get("permission")
            
            if principal_type == "User":
                users_set.add(identifier)
            elif principal_type == "App":
                service_principals_set.add(identifier)
            
            permissions_counter[permission] = permissions_counter.get(permission, 0) + 1
        
        return {
            "dataflow_access": dataflow_access,
            "dataflow_access_errors": errors,
            "summary": {
                "total_dataflows": total_dataflows,
                "personal_workspaces_dataflows_skipped": skipped_personal,
                "dataflows_processed": dataflows_processed,
                "dataflows_with_users": dataflows_with_users,
                "total_access_entries": len(dataflow_access),
                "users_count": len(users_set),
                "service_principals_count": len(service_principals_set),
                "permissions_breakdown": permissions_counter,
                "errors_count": len(errors),
            }
        }