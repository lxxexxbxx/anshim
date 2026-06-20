# anshim/core/analyzers/rule_based.py
"""규칙 기반 분석기 통합 모듈.

Semgrep과 Bandit을 병렬로 실행하고 결과를 통합합니다.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from .bandit_analyzer import BanditAnalyzer
from .models import AnalysisResult, ScanSummary
from .semgrep_analyzer import SemgrepAnalyzer

logger = logging.getLogger(__name__)

# 지원 언어 목록
SUPPORTED_LANGUAGES: list[str] = ["python", "javascript", "typescript", "java"]

# 파일 확장자 매핑
EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
}


class RuleBasedAnalyzer:
    """규칙 기반 정적 분석기.

    Semgrep과 Bandit을 병렬로 실행하여 코드를 분석하고,
    결과를 통합하여 반환합니다.
    """

    def __init__(self) -> None:
        """RuleBasedAnalyzer 초기화."""
        self._semgrep = SemgrepAnalyzer()
        self._bandit = BanditAnalyzer()

    def analyze(
        self,
        target: Path,
        languages: list[str] | None = None,
    ) -> ScanSummary:
        """대상 경로를 분석.

        Semgrep과 Bandit을 병렬로 실행하고 결과를 통합합니다.

        Args:
            target: 분석 대상 파일 또는 디렉토리 경로.
            languages: 분석할 언어 목록. None이면 모든 지원 언어.

        Returns:
            스캔 요약 결과.
        """
        start_time = time.time()

        if languages is None:
            languages = SUPPORTED_LANGUAGES

        # 대상 경로 확인
        target = target.resolve()
        if not target.exists():
            logger.error(f"대상 경로가 존재하지 않습니다: {target}")
            return ScanSummary(
                target_path=str(target),
                total_files=0,
                scanned_files=0,
                results=[],
                duration_seconds=0.0,
            )

        # 파일 수 계산
        total_files, scanned_files = self._count_files(target, languages)
        logger.info(f"스캔 대상: {scanned_files}/{total_files} 파일 ({', '.join(languages)})")

        # 분석기 작업 정의
        all_results: list[AnalysisResult] = []

        # 병렬 실행을 위한 작업 목록
        tasks: list[tuple[str, Callable[[], list[AnalysisResult]]]] = []

        if self._semgrep.is_available():
            tasks.append(("Semgrep", lambda: self._semgrep.analyze(target, languages)))
        else:
            logger.warning("Semgrep이 설치되어 있지 않습니다. Semgrep 분석을 건너뜁니다.")

        # Bandit은 Python만 지원
        if "python" in languages:
            if self._bandit.is_available():
                tasks.append(("Bandit", lambda: self._bandit.analyze(target)))
            else:
                logger.warning("Bandit이 설치되어 있지 않습니다. Bandit 분석을 건너뜁니다.")

        # 분석기가 하나도 없으면 빈 결과 반환
        if not tasks:
            logger.warning("사용 가능한 분석기가 없습니다.")
            return ScanSummary(
                target_path=str(target),
                total_files=total_files,
                scanned_files=scanned_files,
                results=[],
                duration_seconds=time.time() - start_time,
            )

        # 병렬 실행
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(task): name for name, task in tasks
            }

            for future in as_completed(futures):
                analyzer_name = futures[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                    logger.info(f"{analyzer_name} 완료: {len(results)}개 이슈")
                except Exception as e:
                    logger.error(f"{analyzer_name} 실행 중 오류: {e}")

        # 중복 제거 (동일 파일+라인+규칙 기준)
        unique_results = self._deduplicate(all_results)
        logger.info(f"중복 제거 후: {len(unique_results)}개 이슈 (원본: {len(all_results)}개)")

        duration = time.time() - start_time

        return ScanSummary(
            target_path=str(target),
            total_files=total_files,
            scanned_files=scanned_files,
            results=unique_results,
            duration_seconds=duration,
        )

    def _count_files(
        self,
        target: Path,
        languages: list[str],
    ) -> tuple[int, int]:
        """대상 경로의 파일 수를 계산.

        Args:
            target: 대상 경로.
            languages: 스캔할 언어 목록.

        Returns:
            (전체 파일 수, 스캔 대상 파일 수) 튜플.
        """
        if target.is_file():
            ext = target.suffix.lower()
            lang = EXTENSION_TO_LANGUAGE.get(ext)
            if lang and lang in languages:
                return 1, 1
            return 1, 0

        # 디렉토리인 경우
        total_files = 0
        scanned_files = 0

        # 언어별 확장자 목록 생성
        target_extensions: set[str] = set()
        for ext, lang in EXTENSION_TO_LANGUAGE.items():
            if lang in languages:
                target_extensions.add(ext)

        for file_path in target.rglob("*"):
            if file_path.is_file():
                total_files += 1
                if file_path.suffix.lower() in target_extensions:
                    scanned_files += 1

        return total_files, scanned_files

    def _deduplicate(
        self,
        results: list[AnalysisResult],
    ) -> list[AnalysisResult]:
        """결과 목록에서 중복 제거.

        동일한 파일, 라인, 규칙 ID를 가진 결과는 하나만 유지합니다.

        Args:
            results: 원본 결과 목록.

        Returns:
            중복 제거된 결과 목록.
        """
        seen: set[str] = set()
        unique: list[AnalysisResult] = []

        for result in results:
            key = result.unique_key()
            if key not in seen:
                seen.add(key)
                unique.append(result)

        return unique

    def get_status(self) -> dict[str, bool]:
        """분석기 상태 확인.

        Returns:
            분석기 이름과 사용 가능 여부를 담은 딕셔너리.
        """
        return {
            "semgrep": self._semgrep.is_available(),
            "bandit": self._bandit.is_available(),
        }
