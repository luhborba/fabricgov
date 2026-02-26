from typing import Any, Callable
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector
from fabricgov.exceptions import NotFoundError, ForbiddenError

POWERBI_API_SCOPE = "https://analysis.windows.net/powerbi/api/.default"


class WorkloadCollector(BaseCollector):
    """
    Coleta workloads de cada capacidade via Power BI API.

    IMPORTANTE: Esta API é relevante apenas para capacidades Gen1
    (Premium P-SKU, Embedded A-SKU). Capacidades Fabric (F-SKU) não
    suportam esta API e são automaticamente ignoradas.

    API: GET https://api.powerbi.com/v1.0/myorg/capacities/{capacityId}/Workloads

    Campos retornados por workload:
    - capacity_id: UUID da capacidade
    - capacity_name: nome da capacidade
    - capacity_sku: SKU da capacidade (ex: "P1", "A1")
    - workload_name: nome do workload (ex: "Dataflows", "PaginatedReports")
    - state: estado (Enabled, Disabled, Unsupported)
    - max_memory_percentage: % de memória máxima configurada (apenas se Enabled)

    Requer que as capacidades já tenham sido coletadas (capacities_result).

    Uso:
        # Opção 1: passando resultado de CapacityCollector
        capacity_collector = CapacityCollector(auth=auth)
        capacities_result = capacity_collector.collect()

        workload_collector = WorkloadCollector(
            auth=auth,
            capacities_result=capacities_result,
            progress_callback=lambda msg: print(msg)
        )
        result = workload_collector.collect()
    """

    def __init__(
        self,
        auth: AuthProvider,
        capacities_result: dict[str, Any],
        progress_callback: Callable[[str], None] | None = None,
        **kwargs,
    ):
        """
        Args:
            auth: Provedor de autenticação
            capacities_result: Resultado do CapacityCollector.collect()
            progress_callback: Função chamada a cada update de progresso
        """
        super().__init__(
            auth=auth,
            base_url="https://api.powerbi.com",
            **kwargs,
        )
        self._capacities_result = capacities_result
        self._progress = progress_callback or (lambda msg: None)

    def collect(self) -> dict[str, Any]:
        """
        Coleta workloads de todas as capacidades Gen1.

        Returns:
            Dicionário com lista de workloads, erros e summary
        """
        capacities = self._capacities_result.get("capacities", [])
        self._progress(f"Coletando workloads de {len(capacities)} capacidades...")

        workloads: list[dict] = []
        errors: list[dict] = []
        skipped_gen2 = 0

        for cap in capacities:
            cap_id = cap.get("id")
            cap_name = cap.get("displayName", cap_id)
            cap_sku = cap.get("sku", "")

            # F-SKUs são Fabric Gen2 — API de workloads não se aplica
            if cap_sku.upper().startswith("F"):
                self._progress(f"  Ignorando {cap_name} (SKU {cap_sku} — Fabric Gen2)")
                skipped_gen2 += 1
                continue

            try:
                response = self._get(
                    endpoint=f"/v1.0/myorg/capacities/{cap_id}/Workloads",
                    scope=POWERBI_API_SCOPE,
                )
                raw_workloads = response.get("value", [])

                for wl in raw_workloads:
                    workloads.append({
                        "capacity_id": cap_id,
                        "capacity_name": cap_name,
                        "capacity_sku": cap_sku,
                        "workload_name": wl.get("name"),
                        "state": wl.get("state"),
                        "max_memory_percentage": wl.get("maxMemoryPercentageSetByUser"),
                    })

                self._progress(f"  ✓ {cap_name} ({cap_sku}): {len(raw_workloads)} workloads")

            except (NotFoundError, ForbiddenError) as e:
                # 404 pode ocorrer em capacidades que não suportam workloads
                errors.append({
                    "capacity_id": cap_id,
                    "capacity_name": cap_name,
                    "capacity_sku": cap_sku,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                })
                self._progress(f"  ⚠ {cap_name}: {type(e).__name__}")

            except Exception as e:
                errors.append({
                    "capacity_id": cap_id,
                    "capacity_name": cap_name,
                    "capacity_sku": cap_sku,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                })
                self._progress(f"  ⚠ {cap_name}: erro — {e}")

        self._progress(
            f"✓ Concluído: {len(workloads)} workloads coletados, "
            f"{skipped_gen2} capacidades Gen2 ignoradas, {len(errors)} erros"
        )

        return self._build_result(workloads, errors, skipped_gen2, len(capacities))

    def _build_result(
        self,
        workloads: list[dict],
        errors: list[dict],
        skipped_gen2: int,
        total_capacities: int,
    ) -> dict[str, Any]:
        """Monta resultado final com workloads e estatísticas."""
        enabled = [w for w in workloads if w.get("state") == "Enabled"]
        disabled = [w for w in workloads if w.get("state") == "Disabled"]
        unsupported = [w for w in workloads if w.get("state") == "Unsupported"]

        workload_names: dict[str, int] = {}
        for wl in workloads:
            name = wl.get("workload_name", "Unknown")
            workload_names[name] = workload_names.get(name, 0) + 1

        return {
            "workloads": workloads,
            "workloads_errors": errors,
            "summary": {
                "total_capacities": total_capacities,
                "capacities_processed": total_capacities - skipped_gen2,
                "capacities_skipped_gen2": skipped_gen2,
                "total_workloads": len(workloads),
                "enabled": len(enabled),
                "disabled": len(disabled),
                "unsupported": len(unsupported),
                "workload_types": workload_names,
                "errors": len(errors),
            },
        }
