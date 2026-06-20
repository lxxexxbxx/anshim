"""
serve 명령어 - 웹 대시보드 실행.

Next.js 웹 대시보드를 localhost에서 실행합니다.
"""

import logging

import typer

logger = logging.getLogger(__name__)


def serve_command(
    port: int = typer.Option(
        3000,
        "--port",
        "-p",
        help="웹 서버 포트 번호",
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        "-h",
        help="웹 서버 호스트 (기본값: localhost only)",
    ),
    open_browser: bool = typer.Option(
        True,
        "--open/--no-open",
        help="브라우저 자동 열기",
    ),
) -> None:
    """
    웹 대시보드를 시작합니다.

    기본적으로 localhost:3000에서 실행되며, 외부 접근은 차단됩니다.
    스캔 결과를 시각화하고 관리할 수 있습니다.
    """
    typer.echo(f"🌐 웹 대시보드 시작 중...")
    typer.echo(f"   주소: http://{host}:{port}")

    if host != "127.0.0.1" and host != "localhost":
        typer.echo("\n⚠️ 경고: 외부 호스트로 설정되었습니다.", err=True)
        typer.echo("   보안을 위해 기본적으로 localhost만 권장합니다.", err=True)

    # TODO: Sprint 5에서 Next.js 대시보드 구현 예정
    typer.echo("\n🚧 웹 대시보드는 Sprint 5에서 구현 예정입니다.")
    typer.echo("   - 스캔 결과 시각화")
    typer.echo("   - 취약점 상세 조회")
    typer.echo("   - 컴플라이언스 매핑 확인")
    typer.echo("   - 리포트 다운로드")

    typer.echo("\n❌ 현재 버전에서는 웹 대시보드를 사용할 수 없습니다.")
    raise typer.Exit(1)
