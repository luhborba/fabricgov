"""
fabricgov Python API — facade de alto nível para uso programático.

Exemplo de uso::

    from fabricgov import FabricGov

    fg = FabricGov.from_env()

    # Coleta individual
    fg.collect.inventory()
    fg.collect.workspace_access()

    # Coleta completa (equivalente ao CLI 'collect all')
    run_dir = fg.collect.all(days=28)

    # Gerar relatório HTML salvo em arquivo
    fg.report(output_path="reports/governance.html", lang="pt")
    fg.report(output_path="reports/governance.en.html", lang="en")

    # Comparar dois snapshots
    result = fg.diff()                                    # auto-detecta os 2 mais recentes
    result = fg.diff(from_dir="output/20260301_120000",
                     to_dir="output/20260309_143000")
    result.save("output/diff.json")

    # Findings de governança (sem chamadas de API)
    findings = fg.analyze()
    for f in findings:
        print(f["severity"], f["message"])
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Callable

from fabricgov.auth import ServicePrincipalAuth, DeviceFlowAuth
from fabricgov.collectors import (
    WorkspaceInventoryCollector,
    WorkspaceAccessCollector,
    RefreshHistoryCollector,
    RefreshScheduleCollector,
    DomainCollector,
    TagCollector,
    CapacityCollector,
    WorkloadCollector,
    ActivityCollector,
)
# Deprecados — mantidos por compatibilidade retroativa
from fabricgov.collectors.report_access import ReportAccessCollector
from fabricgov.collectors.dataset_access import DatasetAccessCollector
from fabricgov.collectors.dataflow_access import DataflowAccessCollector
from fabricgov.exporters import FileExporter
from fabricgov.exceptions import CheckpointSavedException


# ---------------------------------------------------------------------------
# CollectAPI — sub-namespace de coleta
# ---------------------------------------------------------------------------

class CollectAPI:
    """Sub-namespace de coleta. Acesse via ``fg.collect.<método>``."""

    def __init__(self, auth) -> None:
        self._auth = auth

    # -- helpers internos ----------------------------------------------------

    def _export(
        self,
        result: dict,
        output_dir: str,
        fmt: str,
        run_dir: str | None,
    ) -> Path:
        exporter = FileExporter(format=fmt, output_dir=output_dir, run_dir=run_dir)
        return exporter.export(result, [])

    def _load_inventory(self, output_dir: str) -> dict:
        path = Path(output_dir) / "inventory_result.json"
        if not path.exists():
            raise FileNotFoundError(
                f"inventory_result.json não encontrado em '{output_dir}'. "
                "Execute collect.inventory() primeiro."
            )
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    # -- coletores individuais ------------------------------------------------

    def inventory(
        self,
        output_dir: str = "output",
        format: str = "csv",
        on_progress: Callable[[str], None] | None = None,
        _run_dir: str | None = None,
    ) -> Path:
        """Coleta inventário completo de workspaces e artefatos.

        Returns:
            Path da pasta de output gerada.
        """
        collector = WorkspaceInventoryCollector(
            auth=self._auth,
            progress_callback=on_progress,
        )
        result = collector.collect()

        inv_path = Path(output_dir) / "inventory_result.json"
        inv_path.parent.mkdir(parents=True, exist_ok=True)
        with open(inv_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        return self._export(result, output_dir, format, _run_dir)

    def workspace_access(
        self,
        output_dir: str = "output",
        format: str = "csv",
        resume: bool = True,
        on_progress: Callable[[str], None] | None = None,
        _run_dir: str | None = None,
    ) -> Path:
        """Coleta roles de acesso em workspaces.

        Raises:
            CheckpointSavedException: se atingir rate limit — execute novamente para retomar.
        """
        inv = self._load_inventory(output_dir)
        checkpoint = str(Path(output_dir) / "checkpoint_workspace_access.json") if resume else None
        collector = WorkspaceAccessCollector(
            auth=self._auth,
            inventory_result=inv,
            progress_callback=on_progress,
            checkpoint_file=checkpoint,
        )
        result = collector.collect()
        return self._export(result, output_dir, format, _run_dir)

    def report_access(
        self,
        output_dir: str = "output",
        format: str = "csv",
        resume: bool = True,
        on_progress: Callable[[str], None] | None = None,
        _run_dir: str | None = None,
    ) -> Path:
        """Coleta permissões de acesso em reports.

        .. deprecated::
            Use :meth:`inventory` — os dados de acesso por artefato ficam
            disponíveis na chave ``artifact_users`` do resultado.

        Raises:
            CheckpointSavedException: se atingir rate limit.
        """
        inv = self._load_inventory(output_dir)
        checkpoint = str(Path(output_dir) / "checkpoint_report_access.json") if resume else None
        collector = ReportAccessCollector(
            auth=self._auth,
            inventory_result=inv,
            progress_callback=on_progress,
            checkpoint_file=checkpoint,
        )
        result = collector.collect()
        return self._export(result, output_dir, format, _run_dir)

    def dataset_access(
        self,
        output_dir: str = "output",
        format: str = "csv",
        resume: bool = True,
        on_progress: Callable[[str], None] | None = None,
        _run_dir: str | None = None,
    ) -> Path:
        """Coleta permissões de acesso em datasets.

        .. deprecated::
            Use :meth:`inventory` — os dados de acesso por artefato ficam
            disponíveis na chave ``artifact_users`` do resultado.

        Raises:
            CheckpointSavedException: se atingir rate limit.
        """
        inv = self._load_inventory(output_dir)
        checkpoint = str(Path(output_dir) / "checkpoint_dataset_access.json") if resume else None
        collector = DatasetAccessCollector(
            auth=self._auth,
            inventory_result=inv,
            progress_callback=on_progress,
            checkpoint_file=checkpoint,
        )
        result = collector.collect()
        return self._export(result, output_dir, format, _run_dir)

    def dataflow_access(
        self,
        output_dir: str = "output",
        format: str = "csv",
        resume: bool = True,
        on_progress: Callable[[str], None] | None = None,
        _run_dir: str | None = None,
    ) -> Path:
        """Coleta permissões de acesso em dataflows.

        .. deprecated::
            Use :meth:`inventory` — os dados de acesso por artefato ficam
            disponíveis na chave ``artifact_users`` do resultado.

        Raises:
            CheckpointSavedException: se atingir rate limit.
        """
        inv = self._load_inventory(output_dir)
        checkpoint = str(Path(output_dir) / "checkpoint_dataflow_access.json") if resume else None
        collector = DataflowAccessCollector(
            auth=self._auth,
            inventory_result=inv,
            progress_callback=on_progress,
            checkpoint_file=checkpoint,
        )
        result = collector.collect()
        return self._export(result, output_dir, format, _run_dir)

    def refresh_history(
        self,
        output_dir: str = "output",
        format: str = "csv",
        resume: bool = True,
        history_limit: int = 100,
        on_progress: Callable[[str], None] | None = None,
        _run_dir: str | None = None,
    ) -> Path:
        """Coleta histórico de refreshes de datasets e dataflows.

        Raises:
            CheckpointSavedException: se atingir rate limit.
        """
        inv = self._load_inventory(output_dir)
        checkpoint = str(Path(output_dir) / "checkpoint_refresh_history.json") if resume else None
        collector = RefreshHistoryCollector(
            auth=self._auth,
            inventory_result=inv,
            progress_callback=on_progress,
            checkpoint_file=checkpoint,
            history_limit=history_limit,
        )
        result = collector.collect()
        return self._export(result, output_dir, format, _run_dir)

    def refresh_schedules(
        self,
        output_dir: str = "output",
        format: str = "csv",
        on_progress: Callable[[str], None] | None = None,
        _run_dir: str | None = None,
    ) -> Path:
        """Extrai agendamentos de refresh do inventory (sem chamadas de API)."""
        inv = self._load_inventory(output_dir)
        collector = RefreshScheduleCollector(
            auth=self._auth,
            inventory_result=inv,
            progress_callback=on_progress,
        )
        result = collector.collect()
        return self._export(result, output_dir, format, _run_dir)

    def domains(
        self,
        output_dir: str = "output",
        format: str = "csv",
        on_progress: Callable[[str], None] | None = None,
        _run_dir: str | None = None,
    ) -> Path:
        """Coleta domínios do tenant."""
        collector = DomainCollector(auth=self._auth, progress_callback=on_progress)
        result = collector.collect()
        return self._export(result, output_dir, format, _run_dir)

    def tags(
        self,
        output_dir: str = "output",
        format: str = "csv",
        on_progress: Callable[[str], None] | None = None,
        _run_dir: str | None = None,
    ) -> Path:
        """Coleta tags do tenant."""
        collector = TagCollector(auth=self._auth, progress_callback=on_progress)
        result = collector.collect()
        return self._export(result, output_dir, format, _run_dir)

    def capacities(
        self,
        output_dir: str = "output",
        format: str = "csv",
        on_progress: Callable[[str], None] | None = None,
        _run_dir: str | None = None,
    ) -> Path:
        """Coleta capacidades Premium/Fabric do tenant."""
        collector = CapacityCollector(auth=self._auth, progress_callback=on_progress)
        result = collector.collect()
        return self._export(result, output_dir, format, _run_dir)

    def workloads(
        self,
        output_dir: str = "output",
        format: str = "csv",
        on_progress: Callable[[str], None] | None = None,
        _run_dir: str | None = None,
    ) -> Path:
        """Coleta workloads de capacidades Gen1. Busca capacidades automaticamente."""
        cap_collector = CapacityCollector(auth=self._auth)
        cap_result = cap_collector.collect()
        collector = WorkloadCollector(
            auth=self._auth,
            capacities_result=cap_result,
            progress_callback=on_progress,
        )
        result = collector.collect()
        return self._export(result, output_dir, format, _run_dir)

    def activity(
        self,
        days: int = 7,
        output_dir: str = "output",
        format: str = "csv",
        filter_activity: str | None = None,
        filter_user: str | None = None,
        on_progress: Callable[[str], None] | None = None,
        _run_dir: str | None = None,
    ) -> Path:
        """Coleta log de atividades do tenant (máximo 28 dias).

        Args:
            days: Número de dias para coletar (padrão: 7, máximo: 28).
            filter_activity: Filtrar por tipo de atividade (ex: ``"ViewReport"``).
            filter_user: Filtrar por email do usuário.
        """
        collector = ActivityCollector(
            auth=self._auth,
            days=days,
            filter_activity=filter_activity,
            filter_user=filter_user,
            progress_callback=on_progress,
        )
        result = collector.collect()
        return self._export(result, output_dir, format, _run_dir)

    def all(
        self,
        output_dir: str = "output",
        format: str = "csv",
        days: int = 28,
        history_limit: int = 100,
        resume: bool = True,
        on_progress: Callable[[str], None] | None = None,
    ) -> Path:
        """Executa toda a coleta em sequência numa única pasta de sessão.

        Equivalente ao ``fabricgov collect all --days N``.

        Args:
            output_dir: Diretório raiz onde criar a pasta de sessão.
            format: Formato de export (``"csv"`` ou ``"json"``).
            days: Dias de histórico de atividades (0 = pula atividades).
            history_limit: Máximo de refreshes por artefato.
            resume: Retomar de checkpoint em caso de rate limit.
            on_progress: Callback opcional para mensagens de progresso.

        Returns:
            Path da pasta de sessão criada (ex: ``output/20260313_120000/``).

        Note:
            Se atingir rate limit, ``CheckpointSavedException`` é propagada.
            Execute novamente com ``resume=True`` para retomar.
        """
        run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = str(Path(output_dir) / run_ts)

        def _log(msg: str) -> None:
            if on_progress:
                on_progress(msg)

        _log(f"[fabricgov] Iniciando coleta completa — sessão {run_ts}")

        # 1. Inventário
        _log("[1/5] Inventário...")
        self.inventory(output_dir=output_dir, format=format,
                       on_progress=on_progress, _run_dir=run_dir)

        # 2. Infraestrutura
        _log("[2/5] Infraestrutura...")
        self.domains(output_dir=output_dir, format=format,
                     on_progress=on_progress, _run_dir=run_dir)
        self.tags(output_dir=output_dir, format=format,
                  on_progress=on_progress, _run_dir=run_dir)
        cap_collector = CapacityCollector(auth=self._auth, progress_callback=on_progress)
        cap_result = cap_collector.collect()
        self._export(cap_result, output_dir, format, run_dir)
        wl_collector = WorkloadCollector(auth=self._auth, capacities_result=cap_result,
                                         progress_callback=on_progress)
        self._export(wl_collector.collect(), output_dir, format, run_dir)

        # 3. Acessos
        _log("[3/5] Acessos...")
        self.workspace_access(output_dir=output_dir, format=format, resume=resume,
                              on_progress=on_progress, _run_dir=run_dir)
        self.report_access(output_dir=output_dir, format=format, resume=resume,
                           on_progress=on_progress, _run_dir=run_dir)
        self.dataset_access(output_dir=output_dir, format=format, resume=resume,
                            on_progress=on_progress, _run_dir=run_dir)
        self.dataflow_access(output_dir=output_dir, format=format, resume=resume,
                             on_progress=on_progress, _run_dir=run_dir)

        # 4. Refresh
        _log("[4/5] Refresh...")
        self.refresh_history(output_dir=output_dir, format=format, resume=resume,
                             history_limit=history_limit, on_progress=on_progress,
                             _run_dir=run_dir)
        self.refresh_schedules(output_dir=output_dir, format=format,
                               on_progress=on_progress, _run_dir=run_dir)

        # 5. Atividades
        if days > 0:
            _log(f"[5/5] Atividades ({days} dias)...")
            self.activity(days=days, output_dir=output_dir, format=format,
                          on_progress=on_progress, _run_dir=run_dir)
        else:
            _log("[5/5] Atividades ignoradas (days=0).")

        _log(f"[fabricgov] Coleta concluída — {run_dir}")
        return Path(run_dir)


# ---------------------------------------------------------------------------
# FabricGov — facade principal
# ---------------------------------------------------------------------------

class FabricGov:
    """Facade de alto nível para o fabricgov.

    Exemplo::

        from fabricgov import FabricGov

        fg = FabricGov.from_env()
        run_dir = fg.collect.all(days=28)
        fg.report(output_path=run_dir / "report.html")
    """

    def __init__(self, auth) -> None:
        self._auth = auth
        self.collect = CollectAPI(auth)

    # -- construtores ---------------------------------------------------------

    @classmethod
    def from_env(cls) -> "FabricGov":
        """Autentica via Service Principal lendo credenciais do ``.env``."""
        return cls(ServicePrincipalAuth.from_env())

    @classmethod
    def from_params(
        cls,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ) -> "FabricGov":
        """Autentica via Service Principal com credenciais passadas diretamente."""
        return cls(ServicePrincipalAuth.from_params(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        ))

    @classmethod
    def from_device_flow(cls) -> "FabricGov":
        """Autentica via Device Flow (abre fluxo interativo no browser)."""
        return cls(DeviceFlowAuth())

    @classmethod
    def from_keyvault(
        cls,
        vault_url: str,
        secret_names: dict[str, str] | None = None,
    ) -> "FabricGov":
        """Autentica via Azure Key Vault.

        Args:
            vault_url: URL do Key Vault (ex: ``https://meu-vault.vault.azure.net/``).
            secret_names: Mapeamento dos nomes dos secrets. Se omitido, usa os
                padrões ``fabricgov-tenant-id``, ``fabricgov-client-id``,
                ``fabricgov-client-secret``.
        """
        try:
            from fabricgov.auth.keyvault import KeyVaultAuth
        except ImportError as e:
            raise ImportError(
                "Azure Key Vault requer dependências extras. "
                "Instale com: pip install fabricgov[keyvault]"
            ) from e
        return cls(KeyVaultAuth(vault_url=vault_url, secret_names=secret_names))

    # -- report ---------------------------------------------------------------

    def report(
        self,
        output_path: str | Path,
        lang: str = "pt",
        source_dir: str | Path | None = None,
        output_dir: str = "output",
    ) -> Path:
        """Gera o relatório HTML de governança e salva no caminho indicado.

        Args:
            output_path: Caminho completo do arquivo HTML a gerar.
            lang: Idioma do relatório (``"pt"`` ou ``"en"``).
            source_dir: Pasta com os CSVs coletados. Se omitido, usa o run
                mais recente em ``output_dir``.
            output_dir: Diretório raiz dos runs (usado quando ``source_dir``
                não é informado).

        Returns:
            Path do arquivo HTML gerado.
        """
        from fabricgov.reporters import HtmlReporter
        from fabricgov.cli.report import _find_latest_run

        if source_dir:
            src = Path(source_dir)
        else:
            src = _find_latest_run(output_dir)
            if src is None:
                raise FileNotFoundError(
                    f"Nenhum run encontrado em '{output_dir}'. "
                    "Execute collect.all() ou collect.inventory() primeiro."
                )

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        reporter = HtmlReporter(src)
        reporter.generate(out, lang=lang)
        return out

    # -- diff -----------------------------------------------------------------

    def diff(
        self,
        from_dir: str | Path | None = None,
        to_dir: str | Path | None = None,
        output_dir: str = "output",
        save_to: str | Path | None = None,
    ):
        """Compara dois snapshots e retorna um ``DiffResult``.

        Args:
            from_dir: Snapshot base (o mais antigo). Se omitido, usa o
                penúltimo run em ``output_dir``.
            to_dir: Snapshot atual (o mais recente). Se omitido, usa o
                último run em ``output_dir``.
            output_dir: Diretório raiz dos runs (quando from/to são omitidos).
            save_to: Se informado, salva ``diff.json`` neste caminho.
                Padrão: ``<to_dir>/diff.json``.

        Returns:
            :class:`fabricgov.diff.engine.DiffResult`
        """
        from fabricgov.diff.snapshot import Snapshot, find_run_dirs
        from fabricgov.diff.engine import DiffEngine

        if from_dir and to_dir:
            snap_from = Snapshot(Path(from_dir))
            snap_to = Snapshot(Path(to_dir))
        else:
            runs = find_run_dirs(output_dir)
            if len(runs) < 2:
                raise FileNotFoundError(
                    f"São necessários ao menos 2 runs em '{output_dir}'. "
                    "Use from_dir e to_dir para especificar explicitamente."
                )
            snap_from = Snapshot(runs[-2])
            snap_to = Snapshot(runs[-1])

        result = DiffEngine(snap_from, snap_to).run()

        out_path = Path(save_to) if save_to else snap_to.path / "diff.json"
        result.save(out_path)

        return result

    # -- analyze --------------------------------------------------------------

    def analyze(
        self,
        source_dir: str | Path | None = None,
        output_dir: str = "output",
        save_to: str | Path | None = None,
        lang: str = "pt",
    ) -> list[dict]:
        """Analisa os dados coletados e retorna os findings de governança.

        Não faz chamadas de API — lê apenas os CSVs da pasta de output.

        Args:
            source_dir: Pasta com os CSVs. Se omitido, usa o run mais recente.
            output_dir: Diretório raiz (quando ``source_dir`` não é informado).
            save_to: Se informado, salva ``findings.json`` neste caminho.
            lang: Idioma das mensagens dos findings (``"pt"`` ou ``"en"``).

        Returns:
            Lista de findings, cada um com ``severity``, ``message``,
            ``count`` e ``details``.
        """
        import json as _json
        from fabricgov.reporters.insights import InsightsEngine
        from fabricgov.cli.report import _find_latest_run

        if source_dir:
            src = Path(source_dir)
        else:
            src = _find_latest_run(output_dir)
            if src is None:
                raise FileNotFoundError(
                    f"Nenhum run encontrado em '{output_dir}'. "
                    "Execute collect.all() primeiro."
                )

        ins = InsightsEngine(src).compute()
        findings = ins.findings

        if save_to:
            out = Path(save_to)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                _json.dumps(findings, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        if lang == "en":
            return [
                {**f, "message": f.get("message_en", f["message"])}
                for f in findings
            ]
        return findings
