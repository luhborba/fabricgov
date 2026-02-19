from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exceptions import ForbiddenError, UnauthorizedError

# Tenta autenticar com credenciais inválidas
try:
    auth = ServicePrincipalAuth.from_params(
        tenant_id="invalid-tenant",
        client_id="invalid-client",
        client_secret="invalid-secret"
    )
    collector = WorkspaceInventoryCollector(auth=auth)
    result = collector.collect()
except (ForbiddenError, UnauthorizedError) as e:
    print(f"✓ Erro capturado corretamente:")
    print(f"  Tipo: {type(e).__name__}")
    print(f"  Status: {e.status_code}")
    print(f"  Mensagem: {e.message}")
    print(f"  Endpoint: {e.endpoint}")