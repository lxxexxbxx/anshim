"""
init 명령어 - 초기 설정.

하드웨어 감지, 모델 추천, 컴플라이언스 선택, 설정 파일 생성을 수행합니다.
"""

import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from anshim.core.db import init_db
from anshim.core.models import OllamaClient
from anshim.core.utils.config_manager import ConfigManager
from anshim.core.utils.hardware import detect_hardware, recommend_model

logger = logging.getLogger(__name__)
console = Console()


def init_command(
    force: bool = typer.Option(
        False, "--force", "-f", help="기존 설정을 덮어씁니다"
    ),
) -> None:
    """
    AnShim 초기 설정을 수행합니다.

    1. 하드웨어 감지 (GPU VRAM, RAM)
    2. 추천 모델 안내
    3. 컴플라이언스 선택 (ISMS / ISMS-P)
    4. 설정 파일 생성
    """
    console.print("\n[bold blue]AnShim 초기 설정[/bold blue]")
    console.print()

    # 기존 설정 확인
    config_path = Path.home() / ".anshim" / "config.yaml"
    if config_path.exists() and not force:
        console.print(f"[yellow]설정 파일이 이미 존재합니다: {config_path}[/yellow]")
        console.print("[dim]덮어쓰려면 --force 옵션을 사용하세요.[/dim]")
        console.print()

    # ── 1. 데이터베이스 초기화 ──────────────────────────────
    console.print("[bold]1. 데이터베이스 초기화[/bold]")
    try:
        init_db()
        console.print("   [green]✓[/green] 데이터베이스 초기화 완료")
    except Exception as e:
        logger.error("데이터베이스 초기화 실패: %s", e)
        console.print(f"   [red]✗ 데이터베이스 초기화 실패: {e}[/red]", highlight=False)
        raise typer.Exit(1) from None

    # ── 2. 하드웨어 감지 ───────────────────────────────────
    console.print()
    console.print("[bold]2. 하드웨어 감지[/bold]")
    hw = detect_hardware()

    hw_table = Table(show_header=False, box=None, padding=(0, 3))
    hw_table.add_column("항목", style="dim")
    hw_table.add_column("값")

    hw_table.add_row("RAM", f"{hw.ram_gb:.1f} GB")

    if hw.has_gpu:
        hw_table.add_row("GPU", hw.gpu_name or "감지됨")
        hw_table.add_row("GPU VRAM", f"{hw.gpu_vram_gb:.1f} GB" if hw.gpu_vram_gb else "알 수 없음")
    else:
        hw_table.add_row("GPU", "[dim]감지되지 않음 (CPU 모드)[/dim]")

    console.print(hw_table)

    if hw.detection_errors:
        for err in hw.detection_errors:
            console.print(f"   [dim yellow]경고: {err}[/dim yellow]")

    # ── 3. 모델 추천 ───────────────────────────────────────
    console.print()
    console.print("[bold]3. 추천 모델[/bold]")
    rec_model, rec_reason = recommend_model(hw)

    console.print(f"   모델: [cyan]{rec_model}[/cyan]")
    console.print(f"   이유: [dim]{rec_reason}[/dim]")

    # ── 4. Ollama 상태 확인 ────────────────────────────────
    console.print()
    console.print("[bold]4. Ollama 상태 확인[/bold]")
    ollama = OllamaClient()
    if ollama.is_running():
        console.print("   [green]✓[/green] Ollama 실행 중")
        try:
            installed = ollama.list_models()
            if installed:
                console.print(f"   설치된 모델: {', '.join(installed[:3])}" + (" 외" if len(installed) > 3 else ""))
            else:
                console.print("   [yellow]설치된 모델 없음 — 아래 명령어로 설치하세요[/yellow]")
                console.print(f"   [cyan]anshim models pull {rec_model}[/cyan]")
        except Exception:
            pass
    else:
        console.print("   [yellow]✗ Ollama 미실행[/yellow]")
        console.print("   Ollama 설치: https://ollama.com")
        console.print("   Ollama 시작: [cyan]ollama serve[/cyan]")

    # ── 5. 설정 파일 저장 ─────────────────────────────────
    console.print()
    console.print("[bold]5. 설정 파일 저장[/bold]")

    cfg = ConfigManager(config_path)
    if not config_path.exists() or force:
        cfg.set("model", rec_model)
        cfg.set("compliance", "isms-p")
        cfg.set("ollama_host", "http://localhost:11434")
        cfg.set("db_path", str(Path.home() / ".anshim" / "anshim.db"))
        cfg.save()
        console.print(f"   [green]✓[/green] 설정 저장: {config_path}")
    else:
        console.print(f"   [dim]기존 설정 유지: {config_path}[/dim]")

    # ── 완료 안내 ─────────────────────────────────────────
    console.print()
    next_steps = (
        f"모델 설치:    [cyan]anshim models pull {rec_model}[/cyan]\n"
        "코드 스캔:    [cyan]anshim scan ./src[/cyan]\n"
        "웹 대시보드:  [cyan]anshim serve[/cyan]"
    )
    console.print(
        Panel(
            next_steps,
            title="[bold green]설정 완료 — 다음 단계[/bold green]",
            border_style="green",
        )
    )
