from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import (
    WorkspaceInventoryCollector,
    WorkspaceAccessCollector,
    ReportAccessCollector,
)
from fabricgov.exporters import FileExporter
from datetime import datetime

# Captura log
log_messages = []

def progress(msg: str):
    timestamp_msg = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(timestamp_msg)
    log_messages.append(timestamp_msg)

# Autentica
auth = ServicePrincipalAuth.from_env()

# Coleta inventário completo
print("="*70)
print("ETAPA 1: Coletando inventário de workspaces...")
print("="*70)
inventory_collector = WorkspaceInventoryCollector(
    auth=auth,
    progress_callback=progress
)
inventory_result = inventory_collector.collect()

# Extrai workspace access
print("\n" + "="*70)
print("ETAPA 2: Extraindo acessos de workspaces...")
print("="*70)
workspace_access_collector = WorkspaceAccessCollector(
    auth=auth,
    inventory_result=inventory_result,
    progress_callback=progress
)
workspace_access_result = workspace_access_collector.collect()

print(f"\nTotal de workspaces: {workspace_access_result['summary']['total_workspaces']}")
print(f"Workspaces com usuários: {workspace_access_result['summary']['workspaces_with_users']}")
print(f"Total de acessos: {workspace_access_result['summary']['total_access_entries']}")
print(f"Usuários únicos: {workspace_access_result['summary']['users_count']}")
print(f"Service Principals: {workspace_access_result['summary']['service_principals_count']}")
print(f"Erros: {workspace_access_result['summary']['errors_count']}")
print("\nRoles breakdown:")
for role, count in workspace_access_result['summary']['roles_breakdown'].items():
    print(f"  {role}: {count}")

# Extrai report access
print("\n" + "="*70)
print("ETAPA 3: Extraindo acessos de reports...")
print("="*70)
report_access_collector = ReportAccessCollector(
    auth=auth,
    inventory_result=inventory_result,
    progress_callback=progress
)
report_access_result = report_access_collector.collect()

print(f"\nTotal de reports: {report_access_result['summary']['total_reports']}")
print(f"Reports com usuários: {report_access_result['summary']['reports_with_users']}")
print(f"Total de acessos: {report_access_result['summary']['total_access_entries']}")
print(f"Usuários únicos: {report_access_result['summary']['users_count']}")
print(f"Service Principals: {report_access_result['summary']['service_principals_count']}")
print(f"Erros: {report_access_result['summary']['errors_count']}")
print("\nPermissions breakdown:")
for permission, count in report_access_result['summary']['permissions_breakdown'].items():
    print(f"  {permission}: {count}")

# Exporta tudo
print("\n" + "="*70)
print("ETAPA 4: Exportando resultados...")
print("="*70)

exporter = FileExporter(format="csv", output_dir="output")

# Exporta inventário
inventory_path = exporter.export(inventory_result, log_messages)
print(f"✓ Inventário exportado em: {inventory_path}")

# Exporta workspace access
workspace_access_path = exporter.export(workspace_access_result, [])
print(f"✓ Workspace access exportado em: {workspace_access_path}")

# Exporta report access
report_access_path = exporter.export(report_access_result, [])
print(f"✓ Report access exportado em: {report_access_path}")

print("\n" + "="*70)
print("EXECUÇÃO CONCLUÍDA")
print("="*70)