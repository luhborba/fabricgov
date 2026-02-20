import json
from pathlib import Path
from typing import Any
from datetime import datetime


class Checkpoint:
    """
    Gerencia checkpoints de coleta para permitir retomada após interrupções.
    
    Uso:
        checkpoint = Checkpoint("output/checkpoint_workspace_access.json")
        
        # Verifica se há checkpoint existente
        if checkpoint.exists():
            processed_ids = checkpoint.load()
            print(f"Retomando de checkpoint: {len(processed_ids)} itens já processados")
        else:
            processed_ids = set()
        
        # Durante coleta
        for item_id in all_items:
            if item_id in processed_ids:
                continue  # Pula itens já processados
            
            # Processa item...
            processed_ids.add(item_id)
            
            # Salva checkpoint a cada N itens
            if len(processed_ids) % 50 == 0:
                checkpoint.save(processed_ids, partial_data)
        
        # Ao completar
        checkpoint.clear()
    """

    def __init__(self, checkpoint_file: str | Path):
        """
        Args:
            checkpoint_file: Caminho do arquivo de checkpoint
        """
        self.checkpoint_file = Path(checkpoint_file)

    def exists(self) -> bool:
        """Verifica se existe checkpoint salvo."""
        return self.checkpoint_file.exists()

    def load(self) -> dict[str, Any]:
        """
        Carrega checkpoint existente.
        
        Returns:
            {
                "processed_ids": [...],
                "partial_data": {...},
                "timestamp": "2026-02-19T10:30:00Z",
                "progress": "200/663"
            }
        """
        if not self.exists():
            return {
                "processed_ids": [],
                "partial_data": {},
                "timestamp": None,
                "progress": "0/0"
            }
        
        with open(self.checkpoint_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def save(
        self,
        processed_ids: set[str] | list[str],
        partial_data: dict[str, Any],
        progress: str | None = None
    ) -> None:
        """
        Salva checkpoint no disco.
        
        Args:
            processed_ids: IDs dos itens já processados
            partial_data: Dados coletados até agora (access entries, summary parcial)
            progress: String de progresso (ex: "200/663")
        """
        # Garante que o diretório existe
        self.checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
        
        checkpoint_data = {
            "processed_ids": list(processed_ids),
            "partial_data": partial_data,
            "timestamp": datetime.now().isoformat(),
            "progress": progress or f"{len(processed_ids)}/?"
        }
        
        with open(self.checkpoint_file, "w", encoding="utf-8") as f:
            json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)

    def clear(self) -> None:
        """Remove checkpoint após coleta completa."""
        if self.exists():
            self.checkpoint_file.unlink()

    def get_processed_ids(self) -> set[str]:
        """
        Retorna set de IDs já processados.
        
        Returns:
            set de IDs (workspace_id ou report_id)
        """
        data = self.load()
        return set(data.get("processed_ids", []))

    def get_partial_data(self) -> dict[str, Any]:
        """
        Retorna dados parciais salvos no checkpoint.
        
        Returns:
            Dados coletados até o momento da última interrupção
        """
        data = self.load()
        return data.get("partial_data", {})

