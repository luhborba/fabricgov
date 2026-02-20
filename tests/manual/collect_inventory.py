from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exporters import FileExporter
from datetime import datetime
import json

# Captura log
log_messages = []

def progress(msg: str):
    timestamp_msg = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(timestamp_msg)
    log_messages.append(timestamp_msg)

print("="*70)
print("COLETA DE INVENTÁRIO")
print("="*70)

# Autentica
auth = ServicePrincipalAuth.from_env()

# Coleta inventário completo
inventory_collector = WorkspaceInventoryCollector(
    auth=auth,
    progress_callback=progress
)
inventory_result = inventory_collector.collect()

# Salva resultado em JSON para uso posterior
with open("output/inventory_result.json", "w", encoding="utf-8") as f:
    json.dump(inventory_result, f, indent=2, ensure_ascii=False)

print(f"\n✓ Inventário salvo em: output/inventory_result.json")

# Exporta em CSV também
exporter = FileExporter(format="csv", output_dir="output")
output_path = exporter.export(inventory_result, log_messages)

print(f"✓ CSV exportado em: {output_path}")
print("\n" + "="*70)
print("INVENTÁRIO CONCLUÍDO")
print("="*70)
print(f"Total de workspaces: {inventory_result['summary']['total_workspaces']}")
print(f"Total de itens: {inventory_result['summary']['total_items']}")
print("="*70)