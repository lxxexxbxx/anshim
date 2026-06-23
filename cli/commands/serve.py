"""
serve 명령어 - 웹 대시보드 실행.

FastAPI 백엔드(포트 8000)와 Next.js 프론트엔드(포트 3000)를 함께 실행합니다.
"""

import logging
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

import typer
from rich.console import Console

logger = logging.getLogger(__name__)
console = Console()

# Next.js 웹 디렉토리 경로
_WEB_DIR = Path(__file__).parent.parent.parent / "web"


def _start_api_server(host: str, api_port: int) -> None:
    """FastAPI 백엔드를 별도 스레드에서 실행."""
    try:
        import uvicorn

        uvicorn.run(
            "anshim.core.api.server:app",
            host=host,
            port=api_port,
            log_level="warning",
        )
    except Exception as exc:
        logger.error("API 서버 오류: %s", exc)


def _check_node_modules() -> bool:
    """node_modules 존재 여부 확인."""
    return (_WEB_DIR / "node_modules").exists()


def _npm(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    """npm 명령 실행 (플랫폼 호환)."""
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    return subprocess.run([npm_cmd] + args, **kwargs)  # noqa: S603


def serve_command(
    port: int = typer.Option(3000, "--port", "-p", help="프론트엔드 포트"),
    api_port: int = typer.Option(8000, "--api-port", help="백엔드 API 포트"),
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="바인딩 호스트"),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="브라우저 자동 열기"),
    dev: bool = typer.Option(True, "--dev/--no-dev", help="Next.js 개발 서버 사용"),
) -> None:
    """
    웹 대시보드를 시작합니다.

    FastAPI 백엔드(기본 포트 8000)와 Next.js 프론트엔드(기본 포트 3000)를
    함께 실행합니다. 종료하려면 Ctrl+C를 누르세요.
    """
    if host not in ("127.0.0.1", "localhost"):
        console.print("[yellow]⚠️  경고: 외부 호스트로 설정되었습니다. 보안에 주의하세요.[/yellow]")

    if not _WEB_DIR.exists():
        console.print(f"[red]오류: 웹 디렉토리가 없습니다: {_WEB_DIR}[/red]")
        raise typer.Exit(1)

    # Next.js 의존성 설치 확인
    if not _check_node_modules():
        console.print("[yellow]📦 Next.js 의존성 설치 중 (최초 1회)...[/yellow]")
        result = _npm(["install"], cwd=str(_WEB_DIR))
        if result.returncode != 0:
            console.print("[red]오류: npm install 실패[/red]")
            raise typer.Exit(1)
        console.print("[green]✅ 의존성 설치 완료[/green]")

    console.print("\n[bold]🔐 안심 (AnShim) 대시보드[/bold]")
    console.print(f"   백엔드 API: [cyan]http://{host}:{api_port}[/cyan]")
    console.print(f"   프론트엔드: [cyan]http://{host}:{port}[/cyan]")
    console.print("   종료: [dim]Ctrl+C[/dim]\n")

    # FastAPI 백엔드 스레드 시작
    api_thread = threading.Thread(
        target=_start_api_server,
        args=(host, api_port),
        daemon=True,
    )
    api_thread.start()
    console.print("[green]✅ API 서버 시작됨[/green]")

    # Next.js 프론트엔드 시작
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    next_args = ["run", "dev" if dev else "start"]
    next_env = {
        "NEXT_PUBLIC_API_URL": f"http://{host}:{api_port}",
        "PORT": str(port),
    }

    import os
    env = {**os.environ, **next_env}

    try:
        next_proc = subprocess.Popen(  # noqa: S603
            [npm_cmd] + next_args,
            cwd=str(_WEB_DIR),
            env=env,
        )
        console.print("[green]✅ Next.js 서버 시작됨[/green]")
    except FileNotFoundError:
        console.print("[red]오류: Node.js / npm이 설치되지 않았습니다.[/red]")
        raise typer.Exit(1) from None

    # 서버가 뜰 때까지 잠깐 대기 후 브라우저 열기
    if open_browser:
        time.sleep(3)
        url = f"http://{host}:{port}"
        console.print(f"\n🌐 브라우저 열기: {url}")
        webbrowser.open(url)

    try:
        next_proc.wait()
    except KeyboardInterrupt:
        console.print("\n[yellow]서버를 종료합니다...[/yellow]")
        next_proc.terminate()
        try:
            next_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            next_proc.kill()
