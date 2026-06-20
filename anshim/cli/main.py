"""
AnShim CLI 메인 진입점.

Typer 기반 CLI 인터페이스를 제공합니다.
"""

import typer

from anshim.cli.commands import init, models, report, scan, serve

# 메인 Typer 앱 생성
app = typer.Typer(
    name="anshim",
    help="안심 (AnShim) - 한국 기업을 위한 로컬 LLM 기반 보안 코드 감사 도구",
    no_args_is_help=True,
    pretty_exceptions_enable=True,
)

# 서브 명령어 등록
app.command(name="init", help="초기 설정 (하드웨어 감지 + 모델 추천 + 컴플라이언스 선택)")(
    init.init_command
)
app.command(name="scan", help="디렉토리 스캔 (보안 취약점 분석)")(scan.scan_command)
app.command(name="serve", help="웹 대시보드 실행")(serve.serve_command)

# 서브 앱 등록 (models, report)
app.add_typer(models.app, name="models", help="LLM 모델 관리")
app.add_typer(report.app, name="report", help="스캔 리포트 관리")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="버전 정보 출력"),
) -> None:
    """AnShim CLI 메인 콜백."""
    if version:
        from anshim import __version__

        typer.echo(f"AnShim v{__version__}")
        raise typer.Exit()

    # 명령어 없이 호출된 경우 도움말 표시
    if ctx.invoked_subcommand is None and not version:
        typer.echo(ctx.get_help())


if __name__ == "__main__":
    app()
