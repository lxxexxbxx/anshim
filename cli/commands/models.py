"""
models 명령어 그룹 - LLM 모델 관리.

Ollama를 통해 모델을 설치, 조회, 삭제합니다.
"""

import logging
import subprocess

import typer
from rich.console import Console
from rich.table import Table

from anshim.core.models import (
    SUPPORTED_MODELS,
    OllamaClient,
    OllamaNotRunningError,
    get_model_info,
    get_recommended_model,
)
from anshim.core.utils.hardware import detect_hardware, recommend_model

logger = logging.getLogger(__name__)
console = Console()

app = typer.Typer(help="LLM 모델 관리")


def _check_ollama_running() -> bool:
    """Ollama 실행 여부 확인 및 메시지 출력.

    Returns:
        실행 중이면 True, 아니면 False.
    """
    client = OllamaClient()
    if not client.is_running():
        console.print("[red]Ollama가 실행되지 않습니다.[/red]")
        console.print()
        console.print("Ollama 시작 방법:")
        console.print("  [cyan]ollama serve[/cyan]")
        console.print()
        console.print("Ollama 설치: [link=https://ollama.com]https://ollama.com[/link]")
        return False
    return True


@app.command("list")
def list_models(
    all_models: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="사용 가능한 모든 모델 표시 (설치되지 않은 모델 포함)",
    ),
) -> None:
    """설치된 모델 목록을 표시합니다."""
    client = OllamaClient()

    # Ollama 실행 여부 확인
    installed_models: list[str] = []
    ollama_running = client.is_running()

    if ollama_running:
        try:
            installed_models = client.list_models()
        except OllamaNotRunningError:
            ollama_running = False

    if not ollama_running:
        console.print("[yellow]Ollama가 실행되지 않아 설치된 모델을 확인할 수 없습니다.[/yellow]")
        console.print()

    # 테이블 생성
    table = Table(title="LLM 모델 목록", show_header=True, header_style="bold")
    table.add_column("상태", width=6, justify="center")
    table.add_column("모델명", min_width=20)
    table.add_column("표시명", min_width=20)
    table.add_column("한국어", width=6, justify="center")
    table.add_column("VRAM", width=8, justify="right")
    table.add_column("설명", max_width=40)

    # 지원되는 모델 표시
    for model in SUPPORTED_MODELS:
        # 설치 여부 확인
        is_installed = any(
            m == model.name or m.startswith(model.name.split(":")[0])
            for m in installed_models
        )

        # all_models가 False이면 설치된 것만 표시
        if not all_models and not is_installed:
            continue

        status = "[green]O[/green]" if is_installed else "[dim]-[/dim]"
        korean = "[green]O[/green]" if model.korean_support else "[dim]-[/dim]"
        recommended = " [yellow]*[/yellow]" if model.recommended else ""

        table.add_row(
            status,
            f"{model.name}{recommended}",
            model.display_name,
            korean,
            f"{model.min_vram_gb}GB",
            model.description[:38] + "..." if len(model.description) > 40 else model.description,
        )

    console.print(table)
    console.print()

    # 범례
    console.print("[dim]O 설치됨  - 미설치  * 추천[/dim]")

    if not all_models:
        console.print()
        console.print("[dim]모든 모델 보기: anshim models list --all[/dim]")


@app.command("pull")
def pull_model(
    model_name: str = typer.Argument(
        ...,
        help="설치할 모델 이름 (예: exaone3.5:7.8b)",
    ),
) -> None:
    """모델을 다운로드합니다."""
    if not _check_ollama_running():
        raise typer.Exit(1)

    # 모델 정보 확인
    model_info_obj = get_model_info(model_name)
    if model_info_obj:
        console.print(f"모델: [cyan]{model_info_obj.display_name}[/cyan]")
        console.print(f"필요 VRAM: [yellow]{model_info_obj.min_vram_gb}GB[/yellow]")
        console.print(f"설명: {model_info_obj.description}")
        console.print()

    console.print(f"[bold]모델 다운로드 중: {model_name}[/bold]")
    console.print("[dim]다운로드는 모델 크기에 따라 시간이 걸릴 수 있습니다...[/dim]")
    console.print()

    # subprocess로 ollama pull 실행 (실시간 출력)
    try:
        result = subprocess.run(  # noqa: S603
            ["ollama", "pull", model_name],  # noqa: S607
            check=True,
        )
        if result.returncode == 0:
            console.print()
            console.print(f"[green]모델 '{model_name}' 다운로드 완료![/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]모델 다운로드 실패: {e}[/red]")
        raise typer.Exit(1) from None
    except FileNotFoundError:
        console.print("[red]ollama 명령을 찾을 수 없습니다.[/red]")
        console.print("Ollama 설치: [link=https://ollama.com]https://ollama.com[/link]")
        raise typer.Exit(1) from None


@app.command("recommend")
def recommend_models(
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="상세 정보 출력",
    ),
) -> None:
    """하드웨어에 맞는 모델을 추천합니다."""
    console.print("[bold]모델 추천[/bold]")
    console.print()

    # 하드웨어 감지
    console.print("[dim]하드웨어 감지 중...[/dim]")
    hw = detect_hardware()

    hw_info = f"RAM: {hw.ram_gb:.1f}GB"
    if hw.has_gpu:
        hw_info += f"  |  GPU: {hw.gpu_name}  |  VRAM: {hw.gpu_vram_gb:.1f}GB"
    else:
        hw_info += "  |  GPU: 없음 (CPU 모드)"
    console.print(f"[dim]{hw_info}[/dim]")
    console.print()

    # 하드웨어 기반 추천 모델
    rec_name, rec_reason = recommend_model(hw)
    console.print("[bold cyan]하드웨어 기반 추천 모델[/bold cyan]")
    console.print(f"  모델: [green]{rec_name}[/green]")
    console.print(f"  이유: [dim]{rec_reason}[/dim]")

    model_info_obj = get_model_info(rec_name)
    if model_info_obj:
        console.print(f"  설명: {model_info_obj.description}")
    console.print()

    # VRAM별 추천 가이드
    console.print("[bold cyan]VRAM별 추천 가이드[/bold cyan]")
    console.print()

    recommendations = [
        ("24GB 이상", "exaone3.5:32b 또는 qwen2.5-coder:32b", "최고 품질"),
        ("8-16GB", "exaone3.5:7.8b 또는 qwen2.5-coder:14b", "기본 추천 *"),
        ("4-8GB", "exaone3.5:2.4b 또는 qwen2.5-coder:7b", "경량"),
        ("GPU 없음 (RAM 16GB+)", "exaone3.5:2.4b (CPU 모드)", "느리지만 가능"),
        ("RAM 16GB 미만", "-", "권장하지 않음"),
    ]

    rec_table = Table(show_header=True, header_style="bold")
    rec_table.add_column("환경", min_width=20)
    rec_table.add_column("추천 모델", min_width=35)
    rec_table.add_column("비고", min_width=15)

    for env, models, note in recommendations:
        rec_table.add_row(env, models, note)

    console.print(rec_table)
    console.print()

    # 설치 안내
    console.print("[bold cyan]모델 설치 방법[/bold cyan]")
    console.print(f"  [cyan]anshim models pull {rec_name}[/cyan]")

    if verbose:
        console.print()
        console.print("[bold cyan]모든 지원 모델[/bold cyan]")
        for model in SUPPORTED_MODELS:
            korean = "한국어 O" if model.korean_support else "한국어 X"
            console.print(f"  - {model.name} ({model.min_vram_gb}GB, {korean})")


@app.command("remove")
def remove_model(
    model_name: str = typer.Argument(
        ...,
        help="삭제할 모델 이름",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="확인 없이 삭제",
    ),
) -> None:
    """설치된 모델을 삭제합니다."""
    if not _check_ollama_running():
        raise typer.Exit(1)

    if not force:
        confirm = typer.confirm(f"'{model_name}' 모델을 삭제하시겠습니까?")
        if not confirm:
            console.print("취소되었습니다.")
            raise typer.Exit()

    console.print(f"[bold]모델 삭제 중: {model_name}[/bold]")

    try:
        subprocess.run(  # noqa: S603
            ["ollama", "rm", model_name],  # noqa: S607
            check=True,
            capture_output=True,
            text=True,
        )
        console.print(f"[green]모델 '{model_name}' 삭제 완료![/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]모델 삭제 실패: {e.stderr or e}[/red]")
        raise typer.Exit(1) from None
    except FileNotFoundError:
        console.print("[red]ollama 명령을 찾을 수 없습니다.[/red]")
        raise typer.Exit(1) from None


@app.command("info")
def model_info(
    model_name: str = typer.Argument(
        ...,
        help="정보를 확인할 모델 이름",
    ),
) -> None:
    """모델 상세 정보를 표시합니다."""
    model = get_model_info(model_name)

    if not model:
        console.print(f"[yellow]'{model_name}'은(는) 지원 목록에 없는 모델입니다.[/yellow]")
        console.print()
        console.print("지원되는 모델 목록: [cyan]anshim models list --all[/cyan]")
        console.print()
        console.print("[dim]Ollama에서 지원하는 다른 모델도 사용 가능합니다.[/dim]")
        return

    console.print(f"[bold]{model.display_name}[/bold]")
    console.print()
    console.print(f"  모델명: [cyan]{model.name}[/cyan]")
    console.print(f"  한국어 지원: {'[green]예[/green]' if model.korean_support else '[dim]아니오[/dim]'}")
    console.print(f"  최소 VRAM: [yellow]{model.min_vram_gb}GB[/yellow]")
    console.print(f"  컨텍스트 길이: {model.context_length:,} 토큰")
    console.print(f"  기본 추천: {'[green]예[/green]' if model.recommended else '[dim]아니오[/dim]'}")
    console.print()
    console.print(f"  설명: {model.description}")
    console.print()
    console.print(f"설치: [cyan]anshim models pull {model.name}[/cyan]")
