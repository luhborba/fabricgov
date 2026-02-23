from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
)
from rich.console import Console
from typing import Callable
import time


class ProgressManager:
    """
    Gerencia progress bars com rich para collectors.
    
    Uso:
        with ProgressManager() as pm:
            task_id = pm.add_task("Processando workspaces", total=302)
            
            for i in range(302):
                # ... processa item
                pm.update(task_id, advance=1)
    """
    
    def __init__(self, enabled: bool = True):
        """
        Args:
            enabled: Se False, desabilita progress bars (fallback para print simples)
        """
        self.enabled = enabled
        self.console = Console()
        
        if enabled:
            self.progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=self.console,
            )
        else:
            self.progress = None
    
    def __enter__(self):
        if self.enabled and self.progress:
            self.progress.__enter__()
        return self
    
    def __exit__(self, *args):
        if self.enabled and self.progress:
            self.progress.__exit__(*args)
    
    def add_task(self, description: str, total: int) -> int:
        """
        Adiciona uma nova task.
        
        Args:
            description: Descrição da task
            total: Total de itens a processar
            
        Returns:
            task_id para usar em update()
        """
        if self.enabled and self.progress:
            return self.progress.add_task(description, total=total)
        return -1
    
    def update(self, task_id: int, advance: int = 1, description: str | None = None):
        """
        Atualiza progresso de uma task.
        
        Args:
            task_id: ID retornado por add_task()
            advance: Quantidade a avançar (padrão: 1)
            description: Atualizar descrição (opcional)
        """
        if self.enabled and self.progress and task_id >= 0:
            kwargs = {"advance": advance}
            if description:
                kwargs["description"] = description
            self.progress.update(task_id, **kwargs)
    
    def print(self, message: str):
        """
        Imprime mensagem (compatível com ou sem progress bar).
        
        Args:
            message: Mensagem para imprimir
        """
        if self.enabled and self.progress:
            self.console.print(message)
        else:
            print(message)


def create_progress_callback(
    progress_manager: ProgressManager | None = None
) -> Callable[[str], None]:
    """
    Cria callback de progresso para collectors.
    
    Args:
        progress_manager: ProgressManager ativo (ou None para fallback)
        
    Returns:
        Função callback(msg: str)
    """
    def callback(msg: str):
        if progress_manager:
            progress_manager.print(msg)
        else:
            # Fallback: print simples com timestamp
            from datetime import datetime
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}] {msg}")
    
    return callback