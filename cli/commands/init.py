"""
init 명령어 - 초기 설정.

하드웨어 감지, 모델 추천, 컴플라이언스 선택을 수행합니다.
"""

import logging
from pathlib import Path

import typer

from anshim.core.db import init_db

logger = logging.getLogger(__name__)


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
    typer.echo("🔧 AnShim 초기 설정을 시작합니다...")

    # 데이터베이스 초기화
    typer.echo("\n📦 데이터베이스 초기화 중...")
    try:
        init_db()
        typer.echo("✅ 데이터베이스가 초기화되었습니다.")
    except Exception as e:
        logger.error(f"데이터베이스 초기화 실패: {e}")
        typer.echo(f"❌ 데이터베이스 초기화 실패: {e}", err=True)
        raise typer.Exit(1) from None

    # 하드웨어 감지 (Sprint 6에서 구현 예정)
    typer.echo("\n🖥️ 하드웨어 감지 중...")
    typer.echo("  - GPU: 감지 기능 준비 중 (Sprint 6)")
    typer.echo("  - RAM: 감지 기능 준비 중 (Sprint 6)")

    # 모델 추천 (Sprint 6에서 구현 예정)
    typer.echo("\n🤖 추천 모델:")
    typer.echo("  - 기본 추천: EXAONE 3.5 7.8B (한국어 특화)")
    typer.echo("  - 설치: anshim models pull exaone3.5:7.8b")

    # 컴플라이언스 선택 안내
    typer.echo("\n📋 컴플라이언스 옵션:")
    typer.echo("  - isms     : ISMS (80개 항목)")
    typer.echo("  - isms-p   : ISMS-P (101개 항목, 개인정보 포함)")
    typer.echo("  - owasp    : OWASP Top 10")
    typer.echo("  - cwe      : CWE Top 25")
    typer.echo("\n  사용법: anshim scan ./src --compliance isms-p,owasp")

    # 설정 파일 경로 안내
    config_path = Path.home() / ".anshim"
    typer.echo(f"\n📁 설정 디렉토리: {config_path}")

    typer.echo("\n✅ 초기 설정이 완료되었습니다!")
    typer.echo("   이제 'anshim scan <디렉토리>' 로 스캔을 시작하세요.")
