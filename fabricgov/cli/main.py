import click
from fabricgov.cli.auth import auth
from fabricgov.cli.collect import collect
from fabricgov.cli.report import report_cmd
from fabricgov.cli.analyze import analyze_cmd
from fabricgov.cli.diff import diff_cmd

__version__ = "0.8.1"


@click.group()
@click.version_option(version=__version__, prog_name="fabricgov")
def cli():
    """
    fabricgov - Assessment automatizado de governança em Microsoft Fabric

    \b
    🔐 Autenticação:
      fabricgov auth sp       # Service Principal (.env)
      fabricgov auth device   # Device Flow (interativo)
      fabricgov auth clear    # Limpa autenticação

    \b
    📊 Coleta de Dados:
      fabricgov collect inventory          # Inventário completo
      fabricgov collect workspace-access   # Roles em workspaces
      fabricgov collect report-access      # Permissões em reports
      fabricgov collect dataset-access     # Permissões em datasets
      fabricgov collect dataflow-access    # Permissões em dataflows
      fabricgov collect refresh-history    # Histórico de refreshes
      fabricgov collect refresh-schedules  # Agendamentos configurados
      fabricgov collect activity           # Eventos de atividade (últimos 7 dias)
      fabricgov collect activity --days 28 # Máximo de histórico (28 dias)

    \b
    ⚡ Atalhos:
      fabricgov collect all-access   # Todos os access collectors
      fabricgov collect all-refresh  # Refresh history + schedules
      fabricgov collect all          # Coleta completa em sessão única

    \b
    📊 Relatório e Análise:
      fabricgov report                     # Gera HTML do run mais recente
      fabricgov report --from output/...   # Pasta específica
      fabricgov report --open              # Abre no browser após gerar
      fabricgov analyze                    # Findings de governança no terminal
      fabricgov analyze --from output/...  # Pasta específica
      fabricgov analyze --lang en          # Mensagens em inglês

    \b
    🔍 Comparação de Snapshots:
      fabricgov diff                                          # 2 runs mais recentes
      fabricgov diff --from output/20260301_120000 --to output/20260309_143000

    \b
    📖 Documentação: https://github.com/luhborba/fabricgov
    """
    pass


cli.add_command(auth)
cli.add_command(collect)
cli.add_command(report_cmd, name="report")
cli.add_command(analyze_cmd, name="analyze")
cli.add_command(diff_cmd, name="diff")


if __name__ == '__main__':
    cli()