from typing import Any, Callable
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector

POWERBI_API_SCOPE = "https://analysis.windows.net/powerbi/api/.default"


class CapacityCollector(BaseCollector):
    """
    Coleta todas as capacidades do tenant via Power BI Admin API.

    API: GET https://api.powerbi.com/v1.0/myorg/admin/capacities

    Campos retornados por capacidade:
    - id: UUID da capacidade
    - displayName: nome da capacidade
    - sku: SKU (ex: "A1", "P1", "F2")
    - state: estado (Active, Suspended, Deleted, etc.)
    - region: região Azure (ex: "West Central US")
    - admins: lista de emails dos admins (array de strings)
    - capacityUserAccessRight: direito de acesso do caller (Admin, Assign, None)
    - tenantKeyId: UUID da chave de criptografia (se configurado)

    Uso:
        collector = CapacityCollector(
            auth=auth,
            progress_callback=lambda msg: print(msg)
        )
        result = collector.collect()
    """

    def __init__(
        self,
        auth: AuthProvider,
        progress_callback: Callable[[str], None] | None = None,
        **kwargs,
    ):
        """
        Args:
            auth: Provedor de autenticação
            progress_callback: Função chamada a cada update de progresso
        """
        super().__init__(
            auth=auth,
            base_url="https://api.powerbi.com",
            **kwargs,
        )
        self._progress = progress_callback or (lambda msg: None)

    def collect(self) -> dict[str, Any]:
        """
        Coleta todas as capacidades do tenant.

        Returns:
            Dicionário com lista de capacidades e summary
        """
        self._progress("Coletando capacidades do tenant...")

        capacities = self._paginate(
            endpoint="/v1.0/myorg/admin/capacities",
            scope=POWERBI_API_SCOPE,
        )

        self._progress(f"✓ {len(capacities)} capacidades encontradas")

        return self._build_result(capacities)

    def _build_result(self, capacities: list[dict]) -> dict[str, Any]:
        """Monta resultado final com capacidades e estatísticas."""
        active = [c for c in capacities if c.get("state") == "Active"]
        suspended = [c for c in capacities if c.get("state") == "Suspended"]

        skus: dict[str, int] = {}
        for cap in capacities:
            sku = cap.get("sku", "Unknown")
            skus[sku] = skus.get(sku, 0) + 1

        regions: dict[str, int] = {}
        for cap in capacities:
            region = cap.get("region", "Unknown")
            regions[region] = regions.get(region, 0) + 1

        return {
            "capacities": capacities,
            "summary": {
                "total_capacities": len(capacities),
                "active": len(active),
                "suspended": len(suspended),
                "skus": skus,
                "regions": regions,
            },
        }
