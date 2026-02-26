from typing import Any, Callable, TYPE_CHECKING
from pathlib import Path
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector
from fabricgov.checkpoint import Checkpoint
from fabricgov.exceptions import TooManyRequestsError, CheckpointSavedException

if TYPE_CHECKING:
    from fabricgov.progress import ProgressManager


class WorkspaceAccessCollector(BaseCollector):
    """
    Coleta roles de acesso em workspaces via API Admin com suporte a checkpoint.
    
    Uso com checkpoint (recomendado para ambientes grandes):
        collector = WorkspaceAccessCollector(
            auth=auth,
            inventory_result=inventory_result,
            checkpoint_file="output/checkpoint_workspace_access.json"
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
        progress_manager: "ProgressManager | None" = None,
        **kwargs
    ):
        """
        Args:
            auth: Provedor de autenticação
            inventory_result: Resultado do WorkspaceInventoryCollector
            progress_callback: Função chamada a cada update de progresso
            checkpoint_file: Caminho do checkpoint (habilita modo incremental)
            progress_manager: ProgressManager do rich (opcional, para progress bars)
        """
        super().__init__(
            auth=auth,
            base_url="https://api.powerbi.com",
            **kwargs
        )
        self._inventory_result = inventory_result
        self._progress = progress_callback or (lambda msg: None)
        self._checkpoint = Checkpoint(checkpoint_file) if checkpoint_file else None
        self._progress_manager = progress_manager

    def collect(self) -> dict[str, Any]:
        """
        Coleta roles de acesso em workspaces.
        
        Returns:
            Resultado completo ou parcial (se retomando de checkpoint)
            
        Raises:
            CheckpointSavedException: Quando rate limit interrompe coleta e salva checkpoint
        """
        workspaces = self._inventory_result.get("workspaces", [])
        
        # Filtra Personal Workspaces
        filtered_workspaces = [
            ws for ws in workspaces
            if not (ws.get("name") or "").startswith("PersonalWorkspace")
        ]
        
        # Carrega checkpoint se existir
        processed_ids = set()
        workspace_access = []
        errors = []
        
        if self._checkpoint and self._checkpoint.exists():
            checkpoint_data = self._checkpoint.load()
            processed_ids = set(checkpoint_data.get("processed_ids", []))
            partial_data = checkpoint_data.get("partial_data", {})
            workspace_access = partial_data.get("workspace_access", [])
            errors = partial_data.get("workspace_access_errors", [])
            
            self._progress(f"♻️  Checkpoint detectado: {checkpoint_data['progress']}")
            self._progress(f"   Retomando coleta...")
        
        # Filtra workspaces já processados
        workspaces_to_process = [
            ws for ws in filtered_workspaces
            if ws.get("id") not in processed_ids
        ]
        
        skipped_personal = len(workspaces) - len(filtered_workspaces)
        already_processed = len(processed_ids)
        to_process = len(workspaces_to_process)
        total_expected = len(filtered_workspaces)
        
        self._progress(f"Total de workspaces: {len(workspaces)}")
        self._progress(f"Personal Workspaces ignorados: {skipped_personal}")
        if already_processed > 0:
            self._progress(f"Já processados (checkpoint): {already_processed}")
        self._progress(f"A processar nesta execução: {to_process}")
        
        if to_process == 0:
            self._progress("✓ Todos os workspaces já foram processados!")
            return self._build_result(
                workspace_access, errors, len(workspaces),
                skipped_personal, total_expected, len(processed_ids)
            )
        
        # Coleta acessos
        users_set = set()
        service_principals_set = set()
        roles_counter = {}
        workspaces_with_users = 0

        task_id = -1
        if self._progress_manager:
            task_id = self._progress_manager.add_task("Workspaces", total=to_process)

        for idx, workspace in enumerate(workspaces_to_process, start=1):
            workspace_id = workspace.get("id")
            workspace_name = workspace.get("name")

            if self._progress_manager:
                self._progress_manager.update(task_id, advance=1)
            elif idx % 50 == 0:
                self._progress(f"Processando workspace {idx}/{to_process}...")
            
            try:
                # GET users do workspace
                response = self._get(
                    endpoint=f"/v1.0/myorg/admin/groups/{workspace_id}/users",
                    scope=self.POWERBI_SCOPE,
                )
                
                users = response.get("value", [])
                
                if users:
                    workspaces_with_users += 1
                
                for user in users:
                    email = user.get("emailAddress")
                    identifier = user.get("identifier")
                    principal_type = user.get("principalType", "User")
                    role = user.get("groupUserAccessRight", "Unknown")
                    
                    workspace_access.append({
                        "workspace_id": workspace_id,
                        "workspace_name": workspace_name,
                        "user_email": email,
                        "user_identifier": identifier,
                        "principal_type": principal_type,
                        "role": role,
                    })
                    
                    if principal_type == "User":
                        users_set.add(identifier)
                    elif principal_type == "App":
                        service_principals_set.add(identifier)
                    
                    roles_counter[role] = roles_counter.get(role, 0) + 1
                
                processed_ids.add(workspace_id)
                
                # Salva checkpoint a cada 50 workspaces
                if self._checkpoint and len(processed_ids) % 50 == 0:
                    self._save_checkpoint(
                        processed_ids, workspace_access, errors,
                        already_processed + idx, total_expected
                    )
            
            except TooManyRequestsError as e:
                # Rate limit - salva checkpoint e interrompe
                self._progress(f"⚠️  Rate limit atingido no workspace {idx}")
                self._save_checkpoint(
                    processed_ids, workspace_access, errors,
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
                    "workspace_id": workspace_id,
                    "workspace_name": workspace_name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                })
                if hasattr(e, 'status_code'):
                    errors[-1]["status_code"] = e.status_code
                if hasattr(e, 'response_body'):
                    errors[-1]["response_body"] = e.response_body[:200]
                
                processed_ids.add(workspace_id)
                continue
        
        # Coleta completa - remove checkpoint
        if self._checkpoint:
            self._checkpoint.clear()
            self._progress("🗑️  Checkpoint removido (coleta completa)")
        
        self._progress(f"✓ Coleta concluída: {len(workspace_access)} acessos coletados")
        if errors:
            self._progress(f"⚠️  {len(errors)} workspaces com erro")
        
        return self._build_result(
            workspace_access, errors, len(workspaces),
            skipped_personal, total_expected, workspaces_with_users
        )
    
    def _save_checkpoint(
        self,
        processed_ids: set[str],
        workspace_access: list[dict],
        errors: list[dict],
        current: int,
        total: int
    ) -> None:
        """Salva checkpoint no disco."""
        self._checkpoint.save(
            processed_ids=processed_ids,
            partial_data={
                "workspace_access": workspace_access,
                "workspace_access_errors": errors,
            },
            progress=f"{current}/{total}"
        )
        self._progress(f"💾 Checkpoint salvo: {current}/{total}")
    
    def _build_result(
        self,
        workspace_access: list[dict],
        errors: list[dict],
        total_workspaces: int,
        skipped_personal: int,
        workspaces_processed: int,
        workspaces_with_users: int
    ) -> dict[str, Any]:
        """Monta resultado final."""
        users_set = set()
        service_principals_set = set()
        roles_counter = {}
        
        for access in workspace_access:
            identifier = access.get("user_identifier")
            principal_type = access.get("principal_type")
            role = access.get("role")
            
            if principal_type == "User":
                users_set.add(identifier)
            elif principal_type == "App":
                service_principals_set.add(identifier)
            
            roles_counter[role] = roles_counter.get(role, 0) + 1
        
        return {
            "workspace_access": workspace_access,
            "workspace_access_errors": errors,
            "summary": {
                "total_workspaces": total_workspaces,
                "personal_workspaces_skipped": skipped_personal,
                "workspaces_processed": workspaces_processed,
                "workspaces_with_users": workspaces_with_users,
                "total_access_entries": len(workspace_access),
                "users_count": len(users_set),
                "service_principals_count": len(service_principals_set),
                "roles_breakdown": roles_counter,
                "errors_count": len(errors),
            }
        }