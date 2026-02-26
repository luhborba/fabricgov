import json
from datetime import datetime
from pathlib import Path

SESSION_FILE = "session_state.json"

STEPS = ["inventory", "all-infrastructure", "all-access", "all-refresh"]

CHECKPOINT_PREFIXES = [
    "checkpoint_workspace_access",
    "checkpoint_report_access",
    "checkpoint_dataset_access",
    "checkpoint_dataflow_access",
    "checkpoint_refresh_history",
]


def load_session(output_dir: str) -> dict | None:
    """Carrega session_state.json se existir, retorna None caso contrário."""
    path = Path(output_dir) / SESSION_FILE
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_session(output_dir: str, state: dict) -> None:
    """Salva session_state.json."""
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    state["last_updated"] = datetime.now().isoformat(timespec="seconds")
    with open(path / SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def clear_session(output_dir: str) -> None:
    """Remove session_state.json (sessão concluída)."""
    path = Path(output_dir) / SESSION_FILE
    if path.exists():
        path.unlink()


def create_new_session(output_dir: str, format: str) -> dict:
    """Cria uma nova estrutura de sessão com timestamp como run_dir."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = str(Path(output_dir) / timestamp)
    return {
        "run_dir": run_dir,
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "format": format,
        "steps": {step: {"status": "not_started"} for step in STEPS},
        "last_updated": datetime.now().isoformat(timespec="seconds"),
    }


def mark_step_completed(state: dict, step: str) -> None:
    """Marca um passo como concluído."""
    state["steps"][step] = {
        "status": "completed",
        "completed_at": datetime.now().isoformat(timespec="seconds"),
    }


def mark_step_checkpointed(state: dict, step: str) -> None:
    """Marca um passo como interrompido por checkpoint."""
    state["steps"][step] = {
        "status": "checkpointed",
        "checkpointed_at": datetime.now().isoformat(timespec="seconds"),
    }


def mark_step_failed(state: dict, step: str, error: str = "") -> None:
    """Marca um passo como falho."""
    state["steps"][step] = {
        "status": "failed",
        "failed_at": datetime.now().isoformat(timespec="seconds"),
        "error": error,
    }


def get_step_status(state: dict, step: str) -> str:
    """Retorna o status de um passo ('not_started', 'completed', 'checkpointed', 'failed')."""
    return state["steps"].get(step, {}).get("status", "not_started")


def find_pending_checkpoints(output_dir: str) -> list[str]:
    """Detecta arquivos de checkpoint pendentes no output_dir."""
    base = Path(output_dir)
    found = []
    for prefix in CHECKPOINT_PREFIXES:
        candidate = base / f"{prefix}.json"
        if candidate.exists():
            found.append(candidate.name)
    return found


def is_session_complete(state: dict) -> bool:
    """Retorna True se todos os passos estão concluídos."""
    return all(
        get_step_status(state, step) == "completed"
        for step in STEPS
    )
