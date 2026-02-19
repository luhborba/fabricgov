from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exceptions import AuthenticationError, ForbiddenError, UnauthorizedError

# Testa 1: Tenant inválido (erro na instanciação do auth)
print("Teste 1: Tenant ID inválido")
print("-" * 60)
try:
    auth = ServicePrincipalAuth.from_params(
        tenant_id="invalid-tenant",
        client_id="invalid-client",
        client_secret="invalid-secret"
    )
    collector = WorkspaceInventoryCollector(auth=auth)
    result = collector.collect()
except AuthenticationError as e:
    print(f"✓ Erro capturado corretamente:")
    print(f"  Tipo: {type(e).__name__}")
    print(f"  Mensagem: {str(e)[:200]}...")
    print()

# Teste 2: Credenciais válidas no formato mas sem permissões (erro na API)
print("Teste 2: SP sem permissões de Admin")
print("-" * 60)
try:
    # Usa tenant_id real mas client_id/secret inválidos
    auth = ServicePrincipalAuth.from_env()  # Carrega do .env
    
    # Força um erro 403 tentando acessar endpoint Admin sem permissões
    # (só vai funcionar se seu SP realmente não tiver permissão)
    collector = WorkspaceInventoryCollector(auth=auth)
    
    # Simula chamada que pode dar 403
    # Na prática isso só vai dar erro se o SP não tiver permissão mesmo
    print("  (Este teste precisa de um SP sem permissões Admin para funcionar)")
    print("  Pulando teste 2 — requer configuração específica")
    print()
    
except (ForbiddenError, UnauthorizedError, AuthenticationError) as e:
    print(f"✓ Erro capturado:")
    print(f"  Tipo: {type(e).__name__}")
    if hasattr(e, 'status_code'):
        print(f"  Status: {e.status_code}")
        print(f"  Endpoint: {e.endpoint}")
    print(f"  Mensagem: {str(e)[:200]}...")
    print()

print("="*60)
print("Testes de tratamento de erros concluídos")