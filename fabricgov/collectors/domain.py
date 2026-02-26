from typing import Any, Callable
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector

FABRIC_API_SCOPE = "https://api.fabric.microsoft.com/.default"


class DomainCollector(BaseCollector):
    """
    Coleta todos os domínios do tenant via Fabric Admin API.

    API: GET https://api.fabric.microsoft.com/v1/admin/domains

    Campos retornados por domínio:
    - id: UUID do domínio
    - displayName: nome do domínio
    - description: descrição (pode ser vazio)
    - parentDomainId: UUID do domínio pai (null = domínio raiz)
    - defaultLabelId: UUID do sensitivity label padrão (opcional)

    Uso:
        collector = DomainCollector(
            auth=auth,
            progress_callback=lambda msg: print(msg)
        )
        result = collector.collect()
    """

    def __init__(
        self,
        auth: AuthProvider,
        progress_callback: Callable[[str], None] | None = None,
        non_empty_only: bool = False,
        **kwargs,
    ):
        """
        Args:
            auth: Provedor de autenticação
            progress_callback: Função chamada a cada update de progresso
            non_empty_only: Se True, retorna apenas domínios com pelo menos
                            um workspace contendo itens (padrão: False)
        """
        super().__init__(
            auth=auth,
            base_url="https://api.fabric.microsoft.com",
            **kwargs,
        )
        self._progress = progress_callback or (lambda msg: None)
        self._non_empty_only = non_empty_only

    def collect(self) -> dict[str, Any]:
        """
        Coleta todos os domínios do tenant.

        Returns:
            Dicionário com lista de domínios e summary
        """
        self._progress("Coletando domínios do tenant...")

        params: dict[str, Any] = {"preview": "false"}
        if self._non_empty_only:
            params["nonEmptyOnly"] = "True"

        response = self._get(
            endpoint="/v1/admin/domains",
            scope=FABRIC_API_SCOPE,
            params=params,
        )

        domains = response.get("domains", [])
        self._progress(f"✓ {len(domains)} domínios encontrados")

        return self._build_result(domains)

    def _build_result(self, domains: list[dict]) -> dict[str, Any]:
        """Monta resultado final com domínios e estatísticas."""
        root_domains = [d for d in domains if not d.get("parentDomainId")]
        sub_domains = [d for d in domains if d.get("parentDomainId")]
        with_label = [d for d in domains if d.get("defaultLabelId")]

        return {
            "domains": domains,
            "summary": {
                "total_domains": len(domains),
                "root_domains": len(root_domains),
                "sub_domains": len(sub_domains),
                "domains_with_default_label": len(with_label),
            },
        }
