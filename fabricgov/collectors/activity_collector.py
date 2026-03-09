from typing import Any, Callable
from datetime import datetime, timedelta, timezone
from fabricgov.auth.base import AuthProvider
from fabricgov.collectors.base import BaseCollector


class ActivityCollector(BaseCollector):
    """
    Coleta eventos de atividade do tenant via Power BI Admin API.

    API: GET https://api.powerbi.com/v1.0/myorg/admin/activityevents

    Limitações da API:
    - Janela por request: startDateTime e endDateTime devem ser no mesmo dia UTC
    - Histórico máximo: 28 dias
    - Rate limit: 200 req/hora (compartilhado com demais Admin APIs)
    - Paginação: obrigatória via continuationToken
    - $filter: suporta apenas Activity eq '...', UserId eq '...', e and

    Uso:
        collector = ActivityCollector(
            auth=auth,
            days=7,
            progress_callback=lambda msg: print(msg)
        )
        result = collector.collect()

    Com filtros:
        collector = ActivityCollector(
            auth=auth,
            days=3,
            filter_activity="ViewReport",
            filter_user="user@empresa.com"
        )
    """

    POWERBI_SCOPE = "https://analysis.windows.net/powerbi/api/.default"
    MAX_DAYS = 28

    def __init__(
        self,
        auth: AuthProvider,
        days: int = 7,
        filter_activity: str | None = None,
        filter_user: str | None = None,
        progress_callback: Callable[[str], None] | None = None,
        **kwargs,
    ):
        """
        Args:
            auth: Provedor de autenticação
            days: Número de dias de histórico a coletar (máximo 28)
            filter_activity: Filtrar por tipo de atividade (ex: "ViewReport", "ExportArtifact")
            filter_user: Filtrar por email do usuário (ex: "user@empresa.com")
            progress_callback: Função chamada a cada update de progresso
        """
        super().__init__(
            auth=auth,
            base_url="https://api.powerbi.com",
            **kwargs,
        )
        self._days = min(max(days, 1), self.MAX_DAYS)
        self._filter_activity = filter_activity
        self._filter_user = filter_user
        self._progress = progress_callback or (lambda msg: None)

    def collect(self) -> dict[str, Any]:
        """
        Coleta eventos de atividade dia a dia para o período configurado.

        Itera do dia mais antigo ao mais recente, coletando todos os eventos
        via continuationToken para garantir paginação completa.

        Returns:
            Dicionário com lista de eventos e summary com estatísticas
        """
        now_utc = datetime.now(timezone.utc)
        all_events: list[dict] = []
        days_collected = 0
        days_with_errors = 0

        filters_desc = []
        if self._filter_activity:
            filters_desc.append(f"activity={self._filter_activity}")
        if self._filter_user:
            filters_desc.append(f"user={self._filter_user}")
        filters_str = f" [{', '.join(filters_desc)}]" if filters_desc else ""

        self._progress(f"Coletando {self._days} dias de atividade do tenant{filters_str}...")

        # Coleta do dia mais antigo ao mais recente (excluindo hoje — pode estar incompleto)
        for i in range(self._days, 0, -1):
            day = now_utc - timedelta(days=i)
            day_str = day.strftime("%Y-%m-%d")

            # Formato OData: valor entre aspas simples
            start = f"'{day.strftime('%Y-%m-%dT00:00:00.000')}Z'"
            end   = f"'{day.strftime('%Y-%m-%dT23:59:59.999')}Z'"

            try:
                events = self._collect_day(start, end)
                all_events.extend(events)
                days_collected += 1
                self._progress(f"  {day_str}: {len(events)} eventos")
            except Exception as e:
                days_with_errors += 1
                self._progress(f"  {day_str}: erro — {e}")

        self._progress(f"✓ {len(all_events)} eventos coletados em {days_collected} dias")

        return self._build_result(all_events, days_collected, days_with_errors)

    def _collect_day(self, start_dt: str, end_dt: str) -> list[dict]:
        """
        Coleta todos os eventos de um único dia UTC via continuationToken loop.

        Args:
            start_dt: startDateTime no formato OData (ex: '2024-01-01T00:00:00.000Z')
            end_dt: endDateTime no formato OData (ex: '2024-01-01T23:59:59.999Z')

        Returns:
            Lista de eventos do dia
        """
        events: list[dict] = []
        params: dict[str, Any] = {
            "startDateTime": start_dt,
            "endDateTime": end_dt,
        }

        if self._filter_activity or self._filter_user:
            filters = []
            if self._filter_activity:
                filters.append(f"Activity eq '{self._filter_activity}'")
            if self._filter_user:
                filters.append(f"UserId eq '{self._filter_user}'")
            params["$filter"] = " and ".join(filters)

        continuation_token: str | None = None

        while True:
            if continuation_token:
                # Na continuação, apenas continuationToken é necessário
                params = {"continuationToken": f"'{continuation_token}'"}

            response = self._get(
                endpoint="/v1.0/myorg/admin/activityevents",
                scope=self.POWERBI_SCOPE,
                params=params,
            )

            page_events = response.get("activityEventEntities", [])
            events.extend(page_events)

            continuation_token = response.get("continuationToken")
            if not continuation_token:
                break

        return events

    def _build_result(
        self,
        events: list[dict],
        days_collected: int,
        days_with_errors: int,
    ) -> dict[str, Any]:
        """Monta resultado final com eventos e estatísticas."""
        # Contagem por tipo de atividade
        activity_counts: dict[str, int] = {}
        for ev in events:
            act = ev.get("Activity") or ev.get("Operation") or "Unknown"
            activity_counts[act] = activity_counts.get(act, 0) + 1

        top_activities = sorted(
            [{"activity": k, "count": v} for k, v in activity_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:20]

        # Usuários únicos
        unique_users = len({ev.get("UserId", "") for ev in events if ev.get("UserId")})

        return {
            "activity_events": events,
            "summary": {
                "total_events": len(events),
                "days_requested": self._days,
                "days_collected": days_collected,
                "days_with_errors": days_with_errors,
                "unique_users": unique_users,
                "unique_activity_types": len(activity_counts),
                "top_activities": top_activities,
                "filters_applied": {
                    "activity": self._filter_activity,
                    "user": self._filter_user,
                },
            },
        }
