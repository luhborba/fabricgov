from typing import Any, Callable
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector

FABRIC_API_SCOPE = "https://api.fabric.microsoft.com/.default"


class TagCollector(BaseCollector):
    """
    Coleta todas as tags do tenant via Fabric Admin API.

    API: GET https://api.fabric.microsoft.com/v1/admin/tags

    Campos retornados por tag:
    - id: UUID da tag
    - displayName: nome da tag
    - scope_type: "Tenant" ou "Domain"
    - scope_domain_id: UUID do domínio (apenas quando scope_type = "Domain")

    Suporta paginação via continuationToken.

    Uso:
        collector = TagCollector(
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
            base_url="https://api.fabric.microsoft.com",
            **kwargs,
        )
        self._progress = progress_callback or (lambda msg: None)

    def collect(self) -> dict[str, Any]:
        """
        Coleta todas as tags do tenant.

        Returns:
            Dicionário com lista de tags e summary
        """
        self._progress("Coletando tags do tenant...")

        raw_tags = self._paginate(
            endpoint="/v1/admin/tags",
            scope=FABRIC_API_SCOPE,
        )

        self._progress(f"✓ {len(raw_tags)} tags encontradas")

        tags = [self._flatten_tag(t) for t in raw_tags]

        return self._build_result(tags)

    def _flatten_tag(self, tag: dict) -> dict:
        """
        Achata o objeto de tag para facilitar export em CSV.

        Transforma:
            {"id": "...", "displayName": "...", "scope": {"type": "Domain", "domainId": "..."}}
        Em:
            {"id": "...", "displayName": "...", "scope_type": "Domain", "scope_domain_id": "..."}
        """
        scope = tag.get("scope", {})
        return {
            "id": tag.get("id"),
            "displayName": tag.get("displayName"),
            "scope_type": scope.get("type"),
            "scope_domain_id": scope.get("domainId"),
        }

    def _build_result(self, tags: list[dict]) -> dict[str, Any]:
        """Monta resultado final com tags e estatísticas."""
        tenant_tags = [t for t in tags if t.get("scope_type") == "Tenant"]
        domain_tags = [t for t in tags if t.get("scope_type") == "Domain"]

        return {
            "tags": tags,
            "summary": {
                "total_tags": len(tags),
                "tenant_tags": len(tenant_tags),
                "domain_tags": len(domain_tags),
            },
        }
