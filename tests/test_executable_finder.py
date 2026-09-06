"""executable_finder 모듈 테스트."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from anshim.core.utils.executable_finder import (
    _candidate_suffixes,
    _is_executable,
    _script_dirs,
    find_executable,
)


class TestFindExecutable:
    """find_executable 동작 검증."""

    def test_현재_인터프리터는_찾을_수_있다(self) -> None:
        """python 실행파일은 어떤 환경에서도 탐색 가능해야 한다."""
        name = "python" if sys.platform == "win32" else "python3"
        result = find_executable(name)
        assert result is not None
        assert Path(result).is_file()

    def test_존재하지_않는_이름은_None을_반환한다(self) -> None:
        """찾지 못해도 예외를 던지지 않고 None을 반환해야 한다."""
        assert find_executable("anshim_definitely_not_installed_binary_xyz") is None

    def test_빈_문자열은_None을_반환한다(self) -> None:
        """빈 이름으로 디렉토리를 잘못 매칭하지 않아야 한다."""
        assert find_executable("") is None

    def test_반환값은_절대경로_문자열이다(self) -> None:
        """호출부가 subprocess에 그대로 넘기므로 절대 경로여야 한다."""
        name = "python" if sys.platform == "win32" else "python3"
        result = find_executable(name)
        assert isinstance(result, str)
        assert Path(result).is_absolute()

    def test_PATH에_없어도_스크립트_디렉토리에서_찾는다(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """venv 미활성화 상황(PATH 탐색 실패)의 폴백 경로를 검증한다."""
        suffix = ".exe" if sys.platform == "win32" else ""
        fake = tmp_path / f"semgrep{suffix}"
        fake.write_text("#!/bin/sh\n", encoding="utf-8")
        fake.chmod(0o755)

        monkeypatch.setattr("anshim.core.utils.executable_finder.shutil.which", lambda _name: None)
        monkeypatch.setattr("anshim.core.utils.executable_finder._script_dirs", lambda: [tmp_path])

        result = find_executable("semgrep")
        assert result is not None
        assert Path(result).name.startswith("semgrep")

    def test_PATH_탐색_결과를_우선한다(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """PATH에서 찾으면 스크립트 디렉토리를 뒤지지 않아야 한다."""
        on_path = tmp_path / "bandit_on_path"
        on_path.write_text("", encoding="utf-8")

        monkeypatch.setattr(
            "anshim.core.utils.executable_finder.shutil.which", lambda _name: str(on_path)
        )

        def _fail() -> list[Path]:
            raise AssertionError("PATH에서 찾았으면 스크립트 디렉토리를 탐색하면 안 된다")

        monkeypatch.setattr("anshim.core.utils.executable_finder._script_dirs", _fail)

        assert find_executable("bandit") == str(on_path.resolve())


class TestHelpers:
    """내부 헬퍼 검증."""

    def test_스크립트_디렉토리는_중복_없는_실존_경로다(self) -> None:
        dirs = _script_dirs()
        assert all(d.is_dir() for d in dirs)
        assert len(dirs) == len(set(dirs))

    def test_플랫폼별_확장자_목록(self) -> None:
        suffixes = _candidate_suffixes()
        assert "" in suffixes
        if sys.platform == "win32":
            assert ".exe" in suffixes

    def test_디렉토리는_실행파일이_아니다(self, tmp_path: Path) -> None:
        assert _is_executable(tmp_path) is False

    def test_없는_경로는_실행파일이_아니다(self, tmp_path: Path) -> None:
        assert _is_executable(tmp_path / "nope") is False
