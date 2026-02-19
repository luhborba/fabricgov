from typing import Any, Callable
import time
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector
from fabricgov.exceptions import TooManyRequestsError


class WorkspaceAccessCollector(BaseCollector):
    """
    Coleta roles de acesso em workspaces via API Admin.
    
    Para cada workspace encontrado no inventory, faz:
    GET /v1.0/myorg/admin/groups/{groupId}/users
    
    API: https://learn.microsoft.com/rest/api/power-bi/admin/groups-get-group-users-as-admin
    
    Estratégia de rate limit:
    - Ao detectar 429, pausa 30s e tenta novamente
    - Até 5 tentativas com pausa antes de registrar erro
    
    Uso:
        inventory_result = inventory_collector.collect()
        collector = WorkspaceAccessCollector(
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
        Coleta roles de acesso em todos os workspaces (exceto Personal Workspaces).
        
        Returns:
            {
                "workspace_access": [...],
                "workspace_access_errors": [...],
                "summary": {...}
            }
        """
        workspaces = self._inventory_result.get("workspaces", [])
        
        # Filtra Personal Workspaces
        filtered_workspaces = [
            ws for ws in workspaces
            if not (ws.get("name") or "").startswith("PersonalWorkspace")
        ]
        
        skipped_personal = len(workspaces) - len(filtered_workspaces)
        workspaces_to_process = len(filtered_workspaces)
        
        self._progress(f"Total de workspaces: {len(workspaces)}")
        self._progress(f"Personal Workspaces ignorados: {skipped_personal}")
        self._progress(f"Workspaces a processar: {workspaces_to_process}")
        self._progress(f"Coletando acessos...")

        workspace_access = []
        users_set = set()
        service_principals_set = set()
        roles_counter = {}
        workspaces_with_users = 0
        errors = []
        rate_limit_pauses = 0

        for idx, workspace in enumerate(filtered_workspaces, start=1):
            workspace_id = workspace.get("id")
            workspace_name = workspace.get("name")

            if idx % 50 == 0:
                self._progress(f"Processando workspace {idx}/{workspaces_to_process}...")

            # Tenta até MAX_RATE_LIMIT_RETRIES vezes com pausa ao detectar 429
            success = False
            for retry_attempt in range(self.MAX_RATE_LIMIT_RETRIES):
                try:
                    # GET /v1.0/myorg/admin/groups/{groupId}/users
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

                        # Contabiliza usuários únicos
                        if principal_type == "User":
                            users_set.add(identifier)
                        elif principal_type == "App":
                            service_principals_set.add(identifier)

                        # Contabiliza roles
                        roles_counter[role] = roles_counter.get(role, 0) + 1

                    success = True
                    break  # Sucesso, sai do loop de retry

                except TooManyRequestsError as e:
                    if retry_attempt < self.MAX_RATE_LIMIT_RETRIES - 1:
                        rate_limit_pauses += 1
                        self._progress(
                            f"⚠️  Rate limit no workspace {idx} (tentativa {retry_attempt + 1}/{self.MAX_RATE_LIMIT_RETRIES}). "
                            f"Pausando {self.RATE_LIMIT_SLEEP}s..."
                        )
                        time.sleep(self.RATE_LIMIT_SLEEP)
                        continue
                    else:
                        # Esgotou todas as tentativas
                        error_detail = {
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
            f"✓ Coleta concluída: {len(workspace_access)} acessos em "
            f"{workspaces_with_users}/{workspaces_to_process} workspaces"
        )

        if rate_limit_pauses > 0:
            self._progress(f"⏸️  Total de pausas por rate limit: {rate_limit_pauses}")

        if errors:
            self._progress(f"⚠️  {len(errors)} workspaces com erro")

        # Monta summary
        summary = {
            "total_workspaces": len(workspaces),
            "personal_workspaces_skipped": skipped_personal,
            "workspaces_processed": workspaces_to_process,
            "workspaces_with_users": workspaces_with_users,
            "total_access_entries": len(workspace_access),
            "users_count": len(users_set),
            "service_principals_count": len(service_principals_set),
            "roles_breakdown": roles_counter,
            "rate_limit_pauses": rate_limit_pauses,
            "errors_count": len(errors),
        }

        return {
            "workspace_access": workspace_access,
            "workspace_access_errors": errors,
            "summary": summary,
        }