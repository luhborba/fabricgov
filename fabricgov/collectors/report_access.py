from typing import Any, Callable
from pathlib import Path
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector
from fabricgov.checkpoint import Checkpoint
from fabricgov.exceptions import TooManyRequestsError, CheckpointSavedException


class ReportAccessCollector(BaseCollector):
    """
    Coleta permissões de acesso em reports via API Admin com suporte a checkpoint.
    
    Uso com checkpoint (recomendado para ambientes grandes):
        collector = ReportAccessCollector(
            auth=auth,
            inventory_result=inventory_result,
            checkpoint_file="output/checkpoint_report_access.json"
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
        Coleta permissões de acesso em reports.
        
        Returns:
            Resultado completo ou parcial (se retomando de checkpoint)
            
        Raises:
            CheckpointSavedException: Quando rate limit interrompe coleta e salva checkpoint
        """
        reports = self._inventory_result.get("reports", [])
        
        # Filtra reports de Personal Workspaces
        filtered_reports = [
            rpt for rpt in reports
            if not (rpt.get("workspace_name") or "").startswith("PersonalWorkspace")
        ]
        
        # Carrega checkpoint se existir
        processed_ids = set()
        report_access = []
        errors = []
        
        if self._checkpoint and self._checkpoint.exists():
            checkpoint_data = self._checkpoint.load()
            processed_ids = set(checkpoint_data.get("processed_ids", []))
            partial_data = checkpoint_data.get("partial_data", {})
            report_access = partial_data.get("report_access", [])
            errors = partial_data.get("report_access_errors", [])
            
            self._progress(f"♻️  Checkpoint detectado: {checkpoint_data['progress']}")
            self._progress(f"   Retomando coleta...")
        
        # Filtra reports já processados
        reports_to_process = [
            rpt for rpt in filtered_reports
            if rpt.get("id") not in processed_ids
        ]
        
        skipped_personal = len(reports) - len(filtered_reports)
        already_processed = len(processed_ids)
        to_process = len(reports_to_process)
        total_expected = len(filtered_reports)
        
        self._progress(f"Total de reports: {len(reports)}")
        self._progress(f"Reports em Personal Workspaces ignorados: {skipped_personal}")
        if already_processed > 0:
            self._progress(f"Já processados (checkpoint): {already_processed}")
        self._progress(f"A processar nesta execução: {to_process}")
        
        if to_process == 0:
            self._progress("✓ Todos os reports já foram processados!")
            return self._build_result(
                report_access, errors, len(reports),
                skipped_personal, total_expected, 0
            )
        
        # Coleta acessos
        users_set = set()
        service_principals_set = set()
        permissions_counter = {}
        reports_with_users = 0
        
        for idx, report in enumerate(reports_to_process, start=1):
            report_id = report.get("id")
            report_name = report.get("name")
            workspace_id = report.get("workspace_id")
            workspace_name = report.get("workspace_name")
            
            if idx % 100 == 0:
                self._progress(f"Processando report {idx}/{to_process}...")
            
            try:
                # GET users do report
                response = self._get(
                    endpoint=f"/v1.0/myorg/admin/reports/{report_id}/users",
                    scope=self.POWERBI_SCOPE,
                )
                
                users = response.get("value", [])
                
                if users:
                    reports_with_users += 1
                
                for user in users:
                    email = user.get("emailAddress")
                    identifier = user.get("identifier")
                    principal_type = user.get("principalType", "User")
                    permission = user.get("reportUserAccessRight", "Unknown")
                    
                    report_access.append({
                        "report_id": report_id,
                        "report_name": report_name,
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
                
                processed_ids.add(report_id)
                
                # Salva checkpoint a cada 100 reports
                if self._checkpoint and len(processed_ids) % 100 == 0:
                    self._save_checkpoint(
                        processed_ids, report_access, errors,
                        already_processed + idx, total_expected
                    )
            
            except TooManyRequestsError as e:
                # Rate limit - salva checkpoint e interrompe
                self._progress(f"⚠️  Rate limit atingido no report {idx}")
                self._save_checkpoint(
                    processed_ids, report_access, errors,
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
                    "report_id": report_id,
                    "report_name": report_name,
                    "workspace_id": workspace_id,
                    "workspace_name": workspace_name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                })
                if hasattr(e, 'status_code'):
                    errors[-1]["status_code"] = e.status_code
                if hasattr(e, 'response_body'):
                    errors[-1]["response_body"] = e.response_body[:200]
                
                processed_ids.add(report_id)
                continue
        
        # Coleta completa - remove checkpoint
        if self._checkpoint:
            self._checkpoint.clear()
            self._progress("🗑️  Checkpoint removido (coleta completa)")
        
        self._progress(f"✓ Coleta concluída: {len(report_access)} acessos coletados")
        if errors:
            self._progress(f"⚠️  {len(errors)} reports com erro")
        
        return self._build_result(
            report_access, errors, len(reports),
            skipped_personal, total_expected, reports_with_users
        )
    
    def _save_checkpoint(
        self,
        processed_ids: set[str],
        report_access: list[dict],
        errors: list[dict],
        current: int,
        total: int
    ) -> None:
        """Salva checkpoint no disco."""
        self._checkpoint.save(
            processed_ids=processed_ids,
            partial_data={
                "report_access": report_access,
                "report_access_errors": errors,
            },
            progress=f"{current}/{total}"
        )
        self._progress(f"💾 Checkpoint salvo: {current}/{total}")
    
    def _build_result(
        self,
        report_access: list[dict],
        errors: list[dict],
        total_reports: int,
        skipped_personal: int,
        reports_processed: int,
        reports_with_users: int
    ) -> dict[str, Any]:
        """Monta resultado final."""
        users_set = set()
        service_principals_set = set()
        permissions_counter = {}
        
        for access in report_access:
            identifier = access.get("user_identifier")
            principal_type = access.get("principal_type")
            permission = access.get("permission")
            
            if principal_type == "User":
                users_set.add(identifier)
            elif principal_type == "App":
                service_principals_set.add(identifier)
            
            permissions_counter[permission] = permissions_counter.get(permission, 0) + 1
        
        return {
            "report_access": report_access,
            "report_access_errors": errors,
            "summary": {
                "total_reports": total_reports,
                "personal_workspaces_reports_skipped": skipped_personal,
                "reports_processed": reports_processed,
                "reports_with_users": reports_with_users,
                "total_access_entries": len(report_access),
                "users_count": len(users_set),
                "service_principals_count": len(service_principals_set),
                "permissions_breakdown": permissions_counter,
                "errors_count": len(errors),
            }
        }