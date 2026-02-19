from fabricgov.auth import DeviceFlowAuth
from fabricgov.collectors import WorkspaceInventoryCollector
from fabricgov.exporters import FileExporter
from datetime import datetime

# Captura log messages
log_messages = []

def progress(msg: str):
    timestamp_msg = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(timestamp_msg)
    log_messages.append(timestamp_msg)

# Autentica via Device Flow (multi-tenant automático)
# Não precisa de tenant_id nem client_id — usa padrões públicos
auth = DeviceFlowAuth()

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