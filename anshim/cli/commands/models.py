"""
models 명령어 그룹 - LLM 모델 관리.

Ollama를 통해 모델을 설치, 조회, 삭제합니다.
"""

import logging
from typing import Optional

import typer

logger = logging.getLogger(__name__)

app = typer.Typer(help="LLM 모델 관리")


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
    typer.echo("📋 설치된 모델 목록:")
    typer.echo()

    # TODO: Sprint 2에서 Ollama 연동 후 실제 구현
    typer.echo("  🚧 Ollama 연동은 Sprint 2에서 구현 예정입니다.")
    typer.echo()

    if all_models:
        typer.echo("📋 추천 모델 목록:")
        typer.echo()
        typer.echo("  🌟 한국어 특화:")
        typer.echo("     - exaone3.5:7.8b   (추천, LG AI Research)")
        typer.echo("     - exaone3.5:2.4b   (경량)")
        typer.echo("     - exaone3.5:32b    (고성능)")
        typer.echo()
        typer.echo("  🌐 다국어:")
        typer.echo("     - qwen2.5-coder:7b")
        typer.echo("     - qwen2.5-coder:14b")
        typer.echo("     - qwen2.5-coder:32b")
        typer.echo()
        typer.echo("  📝 기타:")
        typer.echo("     - llama3.2:3b")
        typer.echo("     - deepseek-coder:6.7b")


@app.command("pull")
def pull_model(
    model_name: str = typer.Argument(
        ...,
        help="설치할 모델 이름 (예: exaone3.5:7.8b)",
    ),
) -> None:
    """모델을 다운로드합니다."""
    typer.echo(f"📥 모델 다운로드: {model_name}")
    typer.echo()

    # TODO: Sprint 2에서 Ollama 연동 후 실제 구현
    typer.echo("  🚧 Ollama 연동은 Sprint 2에서 구현 예정입니다.")
    typer.echo()
    typer.echo("  수동 설치 방법:")
    typer.echo(f"    ollama pull {model_name}")


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
    typer.echo("🔍 하드웨어 분석 중...")
    typer.echo()

    # TODO: Sprint 6에서 하드웨어 감지 구현
    typer.echo("  🚧 하드웨어 감지는 Sprint 6에서 구현 예정입니다.")
    typer.echo()
    typer.echo("📋 일반적인 추천 기준:")
    typer.echo()
    typer.echo("  GPU VRAM >= 24GB:")
    typer.echo("    → exaone3.5:32b 또는 qwen2.5-coder:32b (최고 품질)")
    typer.echo()
    typer.echo("  GPU VRAM 8-16GB:")
    typer.echo("    → exaone3.5:7.8b 또는 qwen2.5-coder:14b (기본 추천) ⭐")
    typer.echo()
    typer.echo("  GPU VRAM 4-8GB:")
    typer.echo("    → exaone3.5:2.4b 또는 qwen2.5-coder:7b (경량)")
    typer.echo()
    typer.echo("  GPU 없음 + RAM >= 16GB:")
    typer.echo("    → CPU 모드 exaone3.5:2.4b (느리지만 가능)")
    typer.echo()
    typer.echo("  GPU 없음 + RAM < 16GB:")
    typer.echo("    → ⚠️ 권장하지 않음")


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
    if not force:
        confirm = typer.confirm(f"'{model_name}' 모델을 삭제하시겠습니까?")
        if not confirm:
            typer.echo("취소되었습니다.")
            raise typer.Exit()

    typer.echo(f"🗑️ 모델 삭제: {model_name}")
    typer.echo()

    # TODO: Sprint 2에서 Ollama 연동 후 실제 구현
    typer.echo("  🚧 Ollama 연동은 Sprint 2에서 구현 예정입니다.")
    typer.echo()
    typer.echo("  수동 삭제 방법:")
    typer.echo(f"    ollama rm {model_name}")
