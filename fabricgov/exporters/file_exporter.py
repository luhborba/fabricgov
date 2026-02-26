import json
import csv
from pathlib import Path
from datetime import datetime
from typing import Any, Literal


class FileExporter:
    """
    Exporta resultados de coletores para arquivos JSON ou CSV.
    
    Estrutura de output:
        output/
        └── YYYYMMDD_HHMMSS/
            ├── log.txt
            ├── summary.json
            ├── workspaces.json (ou .csv)
            ├── reports.json (ou .csv)
            └── ...
    
    Uso:
        exporter = FileExporter(format="json", output_dir="output")
        exporter.export(result, log_messages)
    """

    def __init__(
        self,
        format: Literal["json", "csv"] = "json",
        output_dir: str = "output",
    ):
        """
        Args:
            format: "json" ou "csv"
            output_dir: diretório raiz onde criar as pastas timestampadas
        """
        self.format = format
        self.output_dir = Path(output_dir)

    def export(
        self,
        result: dict[str, Any],
        log_messages: list[str],
    ) -> Path:
        """
        Exporta resultado completo para arquivos.
        
        Args:
            result: dicionário retornado por collector.collect()
            log_messages: lista de mensagens de progresso capturadas
        
        Returns:
            Path da pasta criada (ex: output/20260219_163616/)
        """
        # Cria pasta timestampada
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = self.output_dir / timestamp
        run_dir.mkdir(parents=True, exist_ok=True)

        # Exporta log.txt (se houver mensagens)
        if log_messages:
            self._export_log(run_dir, log_messages, result)

        # Exporta summary.json (sempre JSON, independente do formato escolhido)
        if "summary" in result:
            self._export_summary(run_dir, result.get("summary", {}))

        # Detecta tipo de resultado e exporta adequadamente
        self._export_result_data(run_dir, result)

        return run_dir

    def _export_result_data(self, run_dir: Path, result: dict[str, Any]) -> None:
        """
        Detecta o tipo de resultado e exporta os dados adequadamente.
        
        Suporta:
        - WorkspaceInventoryCollector: múltiplas chaves no primeiro nível
        - WorkspaceAccessCollector: chave "workspace_access" + "summary"
        - ReportAccessCollector: chave "report_access" + "summary"
        """
        # Caso 1: Access collectors (workspace_access ou report_access)
        if "workspace_access" in result:
            items = result["workspace_access"]
            if isinstance(items, list) and len(items) > 0:
                self._export_artifact(run_dir, "workspace_access", items)
            
            # Exporta erros se houver
            errors = result.get("workspace_access_errors", [])
            if isinstance(errors, list) and len(errors) > 0:
                self._export_artifact(run_dir, "workspace_access_errors", errors)
            return
        
        if "report_access" in result:
            items = result["report_access"]
            if isinstance(items, list) and len(items) > 0:
                self._export_artifact(run_dir, "report_access", items)
            
            # Exporta erros se houver
            errors = result.get("report_access_errors", [])
            if isinstance(errors, list) and len(errors) > 0:
                self._export_artifact(run_dir, "report_access_errors", errors)
            return
        
        if "dataset_access" in result:
            items = result["dataset_access"]
            if isinstance(items, list) and len(items) > 0:
                self._export_artifact(run_dir, "dataset_access", items)
            
            # Exporta erros se houver
            errors = result.get("dataset_access_errors", [])
            if isinstance(errors, list) and len(errors) > 0:
                self._export_artifact(run_dir, "dataset_access_errors", errors)
            return
        
        if "dataflow_access" in result:
            items = result["dataflow_access"]
            if isinstance(items, list) and len(items) > 0:
                self._export_artifact(run_dir, "dataflow_access", items)
            
            # Exporta erros se houver
            errors = result.get("dataflow_access_errors", [])
            if isinstance(errors, list) and len(errors) > 0:
                self._export_artifact(run_dir, "dataflow_access_errors", errors)
            return
        
        if "refresh_history" in result:
            items = result["refresh_history"]
            if isinstance(items, list) and len(items) > 0:
                self._export_artifact(run_dir, "refresh_history", items)
            
            # Exporta erros se houver
            errors = result.get("refresh_history_errors", [])
            if isinstance(errors, list) and len(errors) > 0:
                self._export_artifact(run_dir, "refresh_history_errors", errors)
            return

        if "refresh_schedules" in result:
            items = result["refresh_schedules"]
            if isinstance(items, list) and len(items) > 0:
                self._export_artifact(run_dir, "refresh_schedules", items)
            return

        if "domains" in result:
            items = result["domains"]
            if isinstance(items, list) and len(items) > 0:
                self._export_artifact(run_dir, "domains", items)
            return

        if "tags" in result:
            items = result["tags"]
            if isinstance(items, list) and len(items) > 0:
                self._export_artifact(run_dir, "tags", items)
            return

        if "capacities" in result:
            items = result["capacities"]
            if isinstance(items, list) and len(items) > 0:
                self._export_artifact(run_dir, "capacities", items)
            return

        # Caso 2: WorkspaceInventoryCollector (múltiplas chaves)
        artifact_keys = [k for k in result.keys() if k not in ["summary"]]
        for key in artifact_keys:
            items = result[key]
            if isinstance(items, list) and len(items) > 0:
                self._export_artifact(run_dir, key, items)

    # ── métodos internos ──────────────────────────────────────────────────

    def _export_log(
        self,
        run_dir: Path,
        log_messages: list[str],
        result: dict[str, Any]
    ) -> None:
        """Gera log.txt com progresso + summary + tipos não encontrados."""
        log_path = run_dir / "log.txt"
        
        with open(log_path, "w", encoding="utf-8") as f:
            # Cabeçalho
            f.write("="*70 + "\n")
            f.write("FABRICGOV - LOG DE EXECUÇÃO\n")
            f.write("="*70 + "\n\n")
            
            # Progresso completo
            f.write("PROGRESSO:\n")
            f.write("-"*70 + "\n")
            for msg in log_messages:
                f.write(f"{msg}\n")
            f.write("\n")
            
            # Summary
            summary = result.get("summary", {})
            f.write("="*70 + "\n")
            f.write("RESUMO:\n")
            f.write("="*70 + "\n")
            f.write(f"Total de workspaces: {summary.get('total_workspaces', 0)}\n")
            f.write(f"Total de itens: {summary.get('total_items', 0)}\n")
            f.write(f"Duração: {summary.get('scan_duration_seconds', 0)}s\n")
            f.write(f"Lotes processados: {summary.get('batches_processed', 0)}\n")
            f.write("\n")
            
            # Artefatos por tipo (só os que têm dados)
            items_by_type = summary.get("items_by_type", {})
            found = {k: v for k, v in items_by_type.items() if v > 0}
            not_found = {k: v for k, v in items_by_type.items() if v == 0}
            
            if found:
                f.write("ARTEFATOS ENCONTRADOS:\n")
                f.write("-"*70 + "\n")
                for artifact_type, count in sorted(found.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  {artifact_type:<35} {count:>6}\n")
                f.write("\n")
            
            if not_found:
                f.write("TIPOS DE ARTEFATOS NÃO ENCONTRADOS:\n")
                f.write("-"*70 + "\n")
                for artifact_type in sorted(not_found.keys()):
                    f.write(f"  {artifact_type}\n")
                f.write("\n")
            
            f.write("="*70 + "\n")
            f.write(f"Arquivos exportados em: {run_dir}\n")
            f.write(f"Formato: {self.format.upper()}\n")
            f.write("="*70 + "\n")

    def _export_summary(self, run_dir: Path, summary: dict[str, Any]) -> None:
        """Exporta summary.json (sempre JSON)."""
        summary_path = run_dir / "summary.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

    def _export_artifact(
        self,
        run_dir: Path,
        artifact_type: str,
        items: list[dict[str, Any]]
    ) -> None:
        """Exporta um tipo de artefato como JSON ou CSV."""
        if self.format == "json":
            self._export_json(run_dir, artifact_type, items)
        else:
            self._export_csv(run_dir, artifact_type, items)

    def _export_json(
        self,
        run_dir: Path,
        artifact_type: str,
        items: list[dict[str, Any]]
    ) -> None:
        """Exporta lista de artefatos como JSON."""
        file_path = run_dir / f"{artifact_type}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2, ensure_ascii=False)

    def _export_csv(
        self,
        run_dir: Path,
        artifact_type: str,
        items: list[dict[str, Any]]
    ) -> None:
        """
        Exporta lista de artefatos como CSV.
        Achata objetos aninhados (ex: sensitivityLabel.labelId vira sensitivityLabel_labelId).
        """
        if not items:
            return
        
        file_path = run_dir / f"{artifact_type}.csv"
        
        # Achata todos os items e coleta todas as chaves possíveis
        flattened_items = [self._flatten_dict(item) for item in items]
        all_keys = set()
        for item in flattened_items:
            all_keys.update(item.keys())
        
        fieldnames = sorted(all_keys)
        
        with open(file_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flattened_items)

    def _flatten_dict(
        self,
        d: dict[str, Any],
        parent_key: str = "",
        sep: str = "_"
    ) -> dict[str, Any]:
        """
        Achata dicionário aninhado.
        Ex: {"user": {"name": "John"}} → {"user_name": "John"}
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Converte listas em strings JSON
                items.append((new_key, json.dumps(v, ensure_ascii=False)))
            else:
                items.append((new_key, v))
        return dict(items)
    