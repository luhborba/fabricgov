from fabricgov.auth import ServicePrincipalAuth
from fabricgov.collectors import DatasetAccessCollector
from fabricgov.exporters import FileExporter
from fabricgov.exceptions import CheckpointSavedException
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
print("COLETA DE ACESSOS EM DATASETS")
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

# Coleta acessos com checkpoint
try:
    collector = DatasetAccessCollector(
        auth=auth,
        inventory_result=inventory_result,
        progress_callback=progress,
        checkpoint_file="output/checkpoint_dataset_access.json"
    )
    
    result = collector.collect()
    
    # Coleta completa - exporta resultado
    exporter = FileExporter(format="csv", output_dir="output")
    output_path = exporter.export(result, [])
    
    print(f"\n✓ Dataset access exportado em: {output_path}")
    print("\n" + "="*70)
    print("COLETA CONCLUÍDA")
    print("="*70)
    print(f"Total de acessos coletados: {len(result['dataset_access'])}")
    print(f"Erros: {len(result['dataset_access_errors'])}")
    print("="*70)

except CheckpointSavedException as e:
    # Rate limit - checkpoint salvo
    print("\n" + "="*70)
    print("COLETA INTERROMPIDA")
    print("="*70)
    print(f"⏹️  {e.progress} datasets processados")
    print(f"💾 Checkpoint: {e.checkpoint_file}")
    print(f"⏰ Aguarde ~1 hora e execute novamente para retomar")
    print("="*70)
    sys.exit(0)

except KeyboardInterrupt:
    # Ctrl+C
    print("\n⚠️  Interrompido pelo usuário (Ctrl+C)")
    sys.exit(1)