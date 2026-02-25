from typing import Any, Callable
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector


class RefreshScheduleCollector(BaseCollector):
    """
    Extrai configurações de agendamento de refreshes do inventory result.
    
    Este coletor NÃO faz chamadas à API — apenas processa dados que já
    foram coletados pelo WorkspaceInventoryCollector.
    
    O Admin Scan API retorna o campo 'refreshSchedule' para datasets e dataflows
    que possuem agendamento configurado.
    
    Uso:
        collector = RefreshScheduleCollector(
            auth=auth,  # Não usado, mas necessário por herança
            inventory_result=inventory_result,
            progress_callback=lambda msg: print(msg)
        )
        result = collector.collect()
    """

    def __init__(
        self,
        auth: AuthProvider,
        inventory_result: dict[str, Any],
        progress_callback: Callable[[str], None] | None = None,
        **kwargs
    ):
        """
        Args:
            auth: Provedor de autenticação (não usado, mas necessário por herança)
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
        Extrai schedules de datasets e dataflows do inventory.
        
        Returns:
            Dicionário com schedules extraídos e summary
        """
        self._progress("Extraindo schedules do inventário...")
        
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
        
        self._progress(f"Total de datasets: {len(datasets)} ({len(datasets) - len(filtered_datasets)} em Personal Workspaces ignorados)")
        self._progress(f"Total de dataflows: {len(dataflows)} ({len(dataflows) - len(filtered_dataflows)} em Personal Workspaces ignorados)")
        
        # Extrai schedules
        schedules = []
        
        # Datasets
        for ds in filtered_datasets:
            schedule = self._extract_dataset_schedule(ds)
            if schedule:
                schedules.append(schedule)
        
        # Dataflows
        for df in filtered_dataflows:
            schedule = self._extract_dataflow_schedule(df)
            if schedule:
                schedules.append(schedule)
        
        self._progress(f"✓ Extração concluída: {len(schedules)} schedules encontrados")
        
        return self._build_result(schedules, len(filtered_datasets), len(filtered_dataflows))
    
    def _extract_dataset_schedule(self, dataset: dict) -> dict | None:
        """
        Extrai schedule de um dataset.
        
        Args:
            dataset: Objeto dataset do inventory
            
        Returns:
            Schedule formatado ou None se não houver schedule
        """
        schedule_raw = dataset.get("refreshSchedule")
        
        if not schedule_raw:
            return None
        
        # Verifica se está habilitado
        enabled = schedule_raw.get("enabled", False)
        
        return {
            "artifact_type": "Dataset",
            "artifact_id": dataset.get("id"),
            "artifact_name": dataset.get("name"),
            "workspace_id": dataset.get("workspace_id"),
            "workspace_name": dataset.get("workspace_name"),
            "enabled": enabled,
            "days": ",".join(schedule_raw.get("days", [])) if schedule_raw.get("days") else None,
            "times": ",".join(schedule_raw.get("times", [])) if schedule_raw.get("times") else None,
            "timezone": schedule_raw.get("localTimeZoneId"),
            "notify_option": schedule_raw.get("notifyOption"),
        }
    
    def _extract_dataflow_schedule(self, dataflow: dict) -> dict | None:
        """
        Extrai schedule de um dataflow.
        
        Args:
            dataflow: Objeto dataflow do inventory
            
        Returns:
            Schedule formatado ou None se não houver schedule
        """
        schedule_raw = dataflow.get("refreshSchedule")
        
        if not schedule_raw:
            return None
        
        # Verifica se está habilitado
        enabled = schedule_raw.get("enabled", False)
        
        return {
            "artifact_type": "Dataflow",
            "artifact_id": dataflow.get("objectId"),
            "artifact_name": dataflow.get("name"),
            "workspace_id": dataflow.get("workspace_id"),
            "workspace_name": dataflow.get("workspace_name"),
            "enabled": enabled,
            "days": ",".join(schedule_raw.get("days", [])) if schedule_raw.get("days") else None,
            "times": ",".join(schedule_raw.get("times", [])) if schedule_raw.get("times") else None,
            "timezone": schedule_raw.get("localTimeZoneId"),
            "notify_option": schedule_raw.get("notifyOption"),
        }
    
    def _build_result(
        self,
        schedules: list[dict],
        total_datasets: int,
        total_dataflows: int
    ) -> dict[str, Any]:
        """Monta resultado final."""
        # Estatísticas
        enabled_count = sum(1 for s in schedules if s.get("enabled"))
        disabled_count = len(schedules) - enabled_count
        
        by_artifact_type = {}
        for schedule in schedules:
            artifact_type = schedule.get("artifact_type")
            by_artifact_type[artifact_type] = by_artifact_type.get(artifact_type, 0) + 1
        
        return {
            "refresh_schedules": schedules,
            "summary": {
                "total_artifacts_scanned": total_datasets + total_dataflows,
                "total_datasets": total_datasets,
                "total_dataflows": total_dataflows,
                "total_schedules_found": len(schedules),
                "schedules_enabled": enabled_count,
                "schedules_disabled": disabled_count,
                "schedules_by_artifact_type": by_artifact_type,
            }
        }