from fabricgov.auth import DeviceFlowAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exporters import FileExporter
from datetime import datetime
import os

# Captura log messages
log_messages = []

def progress(msg: str):
    timestamp_msg = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(timestamp_msg)
    log_messages.append(timestamp_msg)

# Autentica via Device Flow (interativo)
# Requer que o usuário acesse uma URL e digite um código
tenant_id = os.getenv("FABRICGOV_TENANT_ID")
client_id = os.getenv("FABRICGOV_CLIENT_ID")

if not tenant_id or not client_id:
    print("❌ Erro: FABRICGOV_TENANT_ID e FABRICGOV_CLIENT_ID devem estar definidos no .env")
    print("   Device Flow não usa client_secret, mas precisa de tenant_id e client_id")
    exit(1)

auth = DeviceFlowAuth(
    tenant_id=tenant_id,
    client_id=client_id
)

# Instancia coletor com callback de progresso
collector = WorkspaceInventoryCollector(
    auth=auth,
    progress_callback=progress
)

# Executa coleta
result = collector.collect()

# Exporta resultado
exporter = FileExporter(format="csv", output_dir="output")
output_path = exporter.export(result, log_messages)

print(f"\n✓ Arquivos exportados em: {output_path}")