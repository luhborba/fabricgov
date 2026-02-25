from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import RefreshScheduleCollector
from fabricgov.exporters import FileExporter
from datetime import datetime
from pathlib import Path
import json
import sys

# Captura log
log_messages = []

def progress(msg: str):
    timestamp_msg = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(timestamp_msg)
    log_messages.append(timestamp_msg)

print("="*70)
print("COLETA DE SCHEDULES DE REFRESHES")
print("="*70)

# Carrega inventário
inventory_path = Path("output/inventory_result.json")
if not inventory_path.exists():
    print("❌ Erro: Execute collect_inventory.py primeiro!")
    print("   Arquivo não encontrado: output/inventory_result.json")
    sys.exit(1)

with open(inventory_path, "r", encoding="utf-8") as f:
    inventory_result = json.load(f)

# Autentica
auth = ServicePrincipalAuth.from_env()

# Extrai schedules (não faz chamadas à API)
try:
    collector = RefreshScheduleCollector(
        auth=auth,
        inventory_result=inventory_result,
        progress_callback=progress
    )
    
    result = collector.collect()
    
    # Exporta resultado
    exporter = FileExporter(format="csv", output_dir="output")
    output_path = exporter.export(result, [])
    
    print(f"\n✓ Refresh schedules exportado em: {output_path}")
    print("\n" + "="*70)
    print("COLETA CONCLUÍDA")
    print("="*70)
    print(f"Total de schedules encontrados: {len(result['refresh_schedules'])}")
    
    # Mostra breakdown
    summary = result['summary']
    print(f"\nSchedules habilitados: {summary['schedules_enabled']}")
    print(f"Schedules desabilitados: {summary['schedules_disabled']}")
    
    print("\nSchedules por tipo de artefato:")
    for artifact_type, count in summary['schedules_by_artifact_type'].items():
        print(f"  {artifact_type}: {count}")
    
    print("="*70)

except Exception as e:
    print(f"❌ Erro: {e}", err=True)
    sys.exit(1)