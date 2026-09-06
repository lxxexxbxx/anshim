"""외부 실행파일 탐색 유틸리티.

semgrep, bandit 같은 콘솔 스크립트는 PATH에 없어도 현재 파이썬 환경의 스크립트
디렉토리에 설치되어 있는 경우가 많습니다. venv에 설치했지만 venv를 활성화하지 않고
실행하거나, Windows에서 Scripts 디렉토리가 PATH에 없는 상황이 대표적입니다.

shutil.which로 먼저 찾고, 실패하면 현재 인터프리터를 기준으로 스크립트 디렉토리를
직접 탐색합니다. 어느 쪽에서도 찾지 못하면 None을 반환하며, 예외를 던지지 않습니다.
호출부(SemgrepAnalyzer, BanditAnalyzer)가 None을 "미설치"로 해석해 기능을 축소하고
프로그램은 계속 동작합니다(설계 원칙 2: 외부 의존성 없이도 동작한다).
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import sysconfig
from pathlib import Path

logger = logging.getLogger(__name__)

# Windows 콘솔 스크립트에 붙는 확장자. 빈 문자열은 확장자 없는 파일을 의미합니다.
_WINDOWS_SUFFIXES: tuple[str, ...] = (".exe", ".cmd", ".bat", "")
_POSIX_SUFFIXES: tuple[str, ...] = ("",)


def _candidate_suffixes() -> tuple[str, ...]:
    """현재 플랫폼에서 시도할 실행파일 확장자 목록을 반환합니다.

    Returns:
        확장자 튜플. Windows는 .exe/.cmd/.bat/확장자 없음, 그 외는 확장자 없음.
    """
    return _WINDOWS_SUFFIXES if sys.platform == "win32" else _POSIX_SUFFIXES


def _script_dirs() -> list[Path]:
    """현재 파이썬 환경의 스크립트 디렉토리 후보를 중복 없이 반환합니다.

    Returns:
        존재하는 디렉토리 경로 목록. 탐색 우선순위 순서로 정렬되어 있습니다.
    """
    candidates: list[Path] = []

    # 1. 현재 환경의 스크립트 경로 (venv라면 venv 안의 Scripts/bin)
    try:
        scripts_path = sysconfig.get_path("scripts")
    except (KeyError, OSError):
        scripts_path = None
    if scripts_path:
        candidates.append(Path(scripts_path))

    # 2. 인터프리터가 놓인 디렉토리 (venv/bin/python 옆에 콘솔 스크립트가 함께 설치됨)
    if sys.executable:
        candidates.append(Path(sys.executable).parent)

    # 3. sys.prefix 기준 표준 위치 (1, 2가 비표준 배치일 때의 보험)
    bin_name = "Scripts" if sys.platform == "win32" else "bin"
    for prefix in (sys.prefix, getattr(sys, "base_prefix", sys.prefix)):
        if prefix:
            candidates.append(Path(prefix) / bin_name)

    # 4. 사용자 스킴 (pip install --user)
    try:
        user_scripts = sysconfig.get_path("scripts", f"{os.name}_user")
    except (KeyError, ValueError):
        user_scripts = None
    if user_scripts:
        candidates.append(Path(user_scripts))

    seen: set[Path] = set()
    result: list[Path] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved in seen or not resolved.is_dir():
            continue
        seen.add(resolved)
        result.append(resolved)
    return result


def _is_executable(path: Path) -> bool:
    """경로가 실행 가능한 파일인지 확인합니다.

    Args:
        path: 검사할 경로.

    Returns:
        파일이 존재하고 실행 권한이 있으면 True. Windows에서는 존재 여부만 봅니다.
    """
    if not path.is_file():
        return False
    if sys.platform == "win32":
        return True
    return os.access(path, os.X_OK)


def find_executable(name: str) -> str | None:
    """외부 실행파일의 절대 경로를 찾습니다.

    PATH를 먼저 확인하고, 실패하면 현재 파이썬 환경의 스크립트 디렉토리를
    탐색합니다. venv를 활성화하지 않은 상태에서 anshim을 실행하는 경우를
    처리하기 위한 폴백입니다.

    Args:
        name: 실행파일 이름. 확장자는 붙이지 않습니다 (예: "semgrep", "bandit").

    Returns:
        찾은 실행파일의 절대 경로 문자열. 찾지 못하면 None.

    Examples:
        >>> path = find_executable("semgrep")
        >>> path is None or Path(path).is_absolute()
        True
    """
    if not name:
        return None

    # 1. PATH 탐색 (가장 일반적인 경로)
    found = shutil.which(name)
    if found:
        logger.debug("실행파일 발견 (PATH): %s -> %s", name, found)
        return str(Path(found).resolve())

    # 2. 현재 파이썬 환경의 스크립트 디렉토리 탐색
    for script_dir in _script_dirs():
        for suffix in _candidate_suffixes():
            candidate = script_dir / f"{name}{suffix}"
            if _is_executable(candidate):
                resolved = str(candidate.resolve())
                logger.debug("실행파일 발견 (스크립트 디렉토리): %s -> %s", name, resolved)
                return resolved

    logger.debug("실행파일을 찾지 못했습니다: %s", name)
    return None
