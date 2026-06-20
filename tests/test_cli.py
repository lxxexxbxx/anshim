"""
CLI 테스트.

Typer CLI 명령어의 기본 동작을 테스트합니다.
"""

import pytest
from typer.testing import CliRunner

from anshim.cli.main import app

runner = CliRunner()


class TestMainCLI:
    """메인 CLI 테스트."""

    def test_help(self) -> None:
        """--help 옵션 테스트."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "안심" in result.output or "AnShim" in result.output

    def test_version(self) -> None:
        """--version 옵션 테스트."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "AnShim" in result.output
        assert "0.1.0" in result.output

    def test_no_command(self) -> None:
        """명령어 없이 실행 시 도움말 표시."""
        result = runner.invoke(app)
        # Typer no_args_is_help=True로 설정 시 exit_code 0 또는 2 가능
        # 중요한 것은 도움말이 출력되는지 확인
        assert "scan" in result.output or "init" in result.output or "Usage" in result.output


class TestInitCommand:
    """init 명령어 테스트."""

    def test_init_help(self) -> None:
        """init --help 테스트."""
        result = runner.invoke(app, ["init", "--help"])
        assert result.exit_code == 0
        assert "초기 설정" in result.output or "init" in result.output


class TestScanCommand:
    """scan 명령어 테스트."""

    def test_scan_help(self) -> None:
        """scan --help 테스트."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "compliance" in result.output.lower()

    def test_scan_missing_target(self) -> None:
        """대상 디렉토리 없이 실행 시 에러."""
        result = runner.invoke(app, ["scan"])
        assert result.exit_code != 0


class TestModelsCommand:
    """models 명령어 테스트."""

    def test_models_list(self) -> None:
        """models list 테스트."""
        result = runner.invoke(app, ["models", "list"])
        assert result.exit_code == 0
        assert "모델" in result.output

    def test_models_list_all(self) -> None:
        """models list --all 테스트."""
        result = runner.invoke(app, ["models", "list", "--all"])
        assert result.exit_code == 0
        assert "exaone" in result.output.lower()

    def test_models_recommend(self) -> None:
        """models recommend 테스트."""
        result = runner.invoke(app, ["models", "recommend"])
        assert result.exit_code == 0
        assert "추천" in result.output or "GPU" in result.output


class TestReportCommand:
    """report 명령어 테스트."""

    def test_report_list(self) -> None:
        """report list 테스트."""
        result = runner.invoke(app, ["report", "list"])
        assert result.exit_code == 0
        assert "스캔" in result.output

    def test_report_show(self) -> None:
        """report show 테스트."""
        result = runner.invoke(app, ["report", "show", "test-id"])
        assert result.exit_code == 0


class TestServeCommand:
    """serve 명령어 테스트."""

    def test_serve_help(self) -> None:
        """serve --help 테스트."""
        result = runner.invoke(app, ["serve", "--help"])
        assert result.exit_code == 0
        assert "대시보드" in result.output or "port" in result.output.lower()
