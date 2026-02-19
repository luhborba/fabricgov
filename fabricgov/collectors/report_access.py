from typing import Any, Callable
import time
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector
from fabricgov.exceptions import TooManyRequestsError


class ReportAccessCollector(BaseCollector):
    """
    Coleta permissões de acesso em reports via API Admin.
    
    Para cada report encontrado no inventory, faz:
    GET /v1.0/myorg/admin/reports/{reportId}/users
    
    API: https://learn.microsoft.com/rest/api/power-bi/admin/reports-get-report-users-as-admin
    
    Estratégia de rate limit:
    - Ao detectar 429, pausa 30s e tenta novamente
    - Até 5 tentativas com pausa antes de registrar erro
    
    Uso:
        inventory_result = inventory_collector.collect()
        collector = ReportAccessCollector(
            auth=auth,
            inventory_result=inventory_result,
            progress_callback=lambda msg: print(msg)
        )
        result = collector.collect()
    """

    POWERBI_SCOPE = "https://analysis.windows.net/powerbi/api/.default"
    MAX_RATE_LIMIT_RETRIES = 5
    RATE_LIMIT_SLEEP = 30

    def __init__(
        self,
        auth: AuthProvider,
        inventory_result: dict[str, Any],
        progress_callback: Callable[[str], None] | None = None,
        **kwargs
    ):
        """
        Args:
            auth: Provedor de autenticação
            inventory_result: Resultado do WorkspaceInventoryCollector
            progress_callback: Função chamada a cada update de progresso
        """
        super().__init__(
            auth=auth,
            base_url="https://api.powerbi.com",
            **kwargs
        )
        self._inventory_result = inventory_result
        self._progress = progress_callback or (lambda msg: None)

    def collect(self) -> dict[str, Any]:
        """
        Coleta permissões de acesso em todos os reports (exceto de Personal Workspaces).
        
        Returns:
            {
                "report_access": [...],
                "report_access_errors": [...],
                "summary": {...}
            }
        """
        reports = self._inventory_result.get("reports", [])
        
        # Filtra reports de Personal Workspaces
        filtered_reports = [
            rpt for rpt in reports
            if not (rpt.get("workspace_name") or "").startswith("PersonalWorkspace")
        ]
        
        skipped_personal = len(reports) - len(filtered_reports)
        reports_to_process = len(filtered_reports)
        
        self._progress(f"Total de reports: {len(reports)}")
        self._progress(f"Reports em Personal Workspaces ignorados: {skipped_personal}")
        self._progress(f"Reports a processar: {reports_to_process}")
        self._progress(f"Coletando acessos...")

        report_access = []
        users_set = set()
        service_principals_set = set()
        permissions_counter = {}
        reports_with_users = 0
        errors = []
        rate_limit_pauses = 0

        for idx, report in enumerate(filtered_reports, start=1):
            report_id = report.get("id")
            report_name = report.get("name")
            workspace_id = report.get("workspace_id")
            workspace_name = report.get("workspace_name")

            if idx % 100 == 0:
                self._progress(f"Processando report {idx}/{reports_to_process}...")

            # Tenta até MAX_RATE_LIMIT_RETRIES vezes com pausa ao detectar 429
            success = False
            for retry_attempt in range(self.MAX_RATE_LIMIT_RETRIES):
                try:
                    # GET /v1.0/myorg/admin/reports/{reportId}/users
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

                        # Contabiliza usuários únicos
                        if principal_type == "User":
                            users_set.add(identifier)
                        elif principal_type == "App":
                            service_principals_set.add(identifier)

                        # Contabiliza permissões
                        permissions_counter[permission] = permissions_counter.get(permission, 0) + 1

                    success = True
                    break  # Sucesso, sai do loop de retry

                except TooManyRequestsError as e:
                    if retry_attempt < self.MAX_RATE_LIMIT_RETRIES - 1:
                        rate_limit_pauses += 1
                        self._progress(
                            f"⚠️  Rate limit no report {idx} (tentativa {retry_attempt + 1}/{self.MAX_RATE_LIMIT_RETRIES}). "
                            f"Pausando {self.RATE_LIMIT_SLEEP}s..."
                        )
                        time.sleep(self.RATE_LIMIT_SLEEP)
                        continue
                    else:
                        # Esgotou todas as tentativas
                        error_detail = {
                            "report_id": report_id,
                            "report_name": report_name,
                            "workspace_id": workspace_id,
                            "workspace_name": workspace_name,
                            "error_type": "TooManyRequestsError",
                            "error_message": f"Rate limit persistiu após {self.MAX_RATE_LIMIT_RETRIES} tentativas",
                            "status_code": 429,
                        }
                        errors.append(error_detail)
                        break

                except Exception as e:
                    error_detail = {
                        "report_id": report_id,
                        "report_name": report_name,
                        "workspace_id": workspace_id,
                        "workspace_name": workspace_name,
                        "error_type": type(e).__name__,
                        "error_message": str(e),
                    }
                    
                    if hasattr(e, 'status_code'):
                        error_detail["status_code"] = e.status_code
                    if hasattr(e, 'response_body'):
                        error_detail["response_body"] = e.response_body[:200]
                    
                    errors.append(error_detail)
                    break

        self._progress(
            f"✓ Coleta concluída: {len(report_access)} acessos em "
            f"{reports_with_users}/{reports_to_process} reports"
        )

        if rate_limit_pauses > 0:
            self._progress(f"⏸️  Total de pausas por rate limit: {rate_limit_pauses}")

        if errors:
            self._progress(f"⚠️  {len(errors)} reports com erro")

        # Monta summary
        summary = {
            "total_reports": len(reports),
            "personal_workspaces_reports_skipped": skipped_personal,
            "reports_processed": reports_to_process,
            "reports_with_users": reports_with_users,
            "total_access_entries": len(report_access),
            "users_count": len(users_set),
            "service_principals_count": len(service_principals_set),
            "permissions_breakdown": permissions_counter,
            "rate_limit_pauses": rate_limit_pauses,
            "errors_count": len(errors),
        }

        return {
            "report_access": report_access,
            "report_access_errors": errors,
            "summary": summary,
        }