from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from datetime import datetime

def progress(msg: str):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

# Autentica via .env
auth = ServicePrincipalAuth.from_env()

# Instancia coletor com callback de progresso
collector = WorkspaceInventoryCollector(
    auth=auth,
    progress_callback=progress
)

# Executa coleta
result = collector.collect()

# Exibe resumo
print("\n" + "="*60)
print("RESULTADO:")
print(f"Total de workspaces: {result['summary']['total_workspaces']}")
print(f"Total de itens: {result['summary']['total_items']}")
print(f"Duração: {result['summary']['scan_duration_seconds']}s")
print(f"Lotes processados: {result['summary']['batches_processed']}")
print("="*60)

# Exibe breakdown por tipo (só os que têm dados)
print("\nARTEFATOS POR TIPO:")
items_by_type = result['summary']['items_by_type']
for artifact_type, count in sorted(items_by_type.items(), key=lambda x: x[1], reverse=True):
    if count > 0:
        print(f"  {artifact_type:<30} {count:>6}")
print("="*60)