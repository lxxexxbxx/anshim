# anshim/core/analyzers/bandit_analyzer.py
"""Bandit 기반 Python 보안 분석기 래퍼."""

import json
import logging
import subprocess
from pathlib import Path

from anshim.core.utils.executable_finder import find_executable

from .models import AnalysisResult

logger = logging.getLogger(__name__)

# Bandit 심각도 매핑
SEVERITY_MAP: dict[str, str] = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

# Bandit 신뢰도 매핑
CONFIDENCE_MAP: dict[str, str] = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


class BanditAnalyzer:
    """Bandit을 이용한 Python 보안 분석기.

    Bandit CLI를 subprocess로 실행하여 Python 코드를 분석하고,
    결과를 AnalysisResult 형식으로 변환합니다.
    """

    def __init__(self) -> None:
        """BanditAnalyzer 초기화."""
        self._bandit_path: str | None = find_executable("bandit")

    def is_available(self) -> bool:
        """Bandit 설치 여부 확인.

        Returns:
            Bandit이 설치되어 있으면 True.
        """
        return self._bandit_path is not None

    def analyze(self, target: Path) -> list[AnalysisResult]:
        """대상 경로를 Bandit으로 분석 (Python 전용).

        Args:
            target: 분석 대상 파일 또는 디렉토리 경로.

        Returns:
            분석 결과 목록.
        """
        if not self.is_available():
            logger.warning("Bandit이 설치되어 있지 않습니다. 'pip install bandit'로 설치하세요.")
            return []

        if not target.exists():
            logger.warning(f"대상 경로가 존재하지 않습니다: {target}")
            return []

        # Python 파일 존재 여부 확인
        if not self._has_python_files(target):
            logger.info("Python 파일이 없습니다. Bandit 분석을 건너뜁니다.")
            return []

        try:
            # Bandit 명령 구성
            cmd = [
                self._bandit_path or "bandit",
                "-r",  # 재귀적 스캔
                "-f", "json",  # JSON 출력
                "-q",  # 조용한 모드 (배너 없음)
                str(target),
            ]

            logger.debug(f"Bandit 실행: {' '.join(cmd)}")

            # Bandit 실행
            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5분 타임아웃
            )

            # Bandit은 이슈 발견 시 exit code 1을 반환
            # JSON 출력이 있으면 파싱 시도
            if result.stdout:
                return self._parse_output(result.stdout)

            # 이슈가 없는 경우
            if result.returncode == 0:
                logger.info("Bandit 분석 완료: 이슈 없음")
                return []

            # 에러 발생
            if result.stderr:
                logger.debug(f"Bandit stderr: {result.stderr}")

            return []

        except subprocess.TimeoutExpired:
            logger.error("Bandit 실행 시간이 초과되었습니다 (5분).")
            return []
        except FileNotFoundError:
            logger.error("Bandit 실행 파일을 찾을 수 없습니다.")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Bandit 출력 JSON 파싱 실패: {e}")
            return []
        except Exception as e:
            logger.error(f"Bandit 분석 중 오류 발생: {e}")
            return []

    def _has_python_files(self, target: Path) -> bool:
        """대상 경로에 Python 파일이 있는지 확인.

        Args:
            target: 확인할 경로.

        Returns:
            Python 파일이 있으면 True.
        """
        if target.is_file():
            return target.suffix.lower() == ".py"

        # 디렉토리인 경우 재귀적으로 Python 파일 검색
        for _py_file in target.rglob("*.py"):
            return True
        return False

    def _parse_output(self, output: str) -> list[AnalysisResult]:
        """Bandit JSON 출력을 AnalysisResult 목록으로 변환.

        Args:
            output: Bandit JSON 출력 문자열.

        Returns:
            변환된 AnalysisResult 목록.
        """
        results: list[AnalysisResult] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            logger.error("Bandit 출력을 JSON으로 파싱할 수 없습니다.")
            return []

        # 결과 목록 추출
        findings = data.get("results", [])

        for finding in findings:
            try:
                # 심각도 매핑
                raw_severity = finding.get("issue_severity", "LOW")
                severity = SEVERITY_MAP.get(raw_severity.upper(), "low")

                # 신뢰도 매핑
                raw_confidence = finding.get("issue_confidence", "MEDIUM")
                confidence = CONFIDENCE_MAP.get(raw_confidence.upper(), "medium")

                # 코드 스니펫 추출
                code_snippet = finding.get("code", None)

                # 테스트 ID 생성 (예: B303)
                test_id = finding.get("test_id", "")
                test_name = finding.get("test_name", "")
                rule_id = f"bandit.{test_id}" if test_id else f"bandit.{test_name}"

                # line_range 안전하게 추출
                line_range = finding.get("line_range", [])
                line_end = None
                if line_range and len(line_range) >= 2:
                    line_end = line_range[-1]  # 마지막 라인 번호

                result = AnalysisResult(
                    rule_id=rule_id,
                    title=finding.get("issue_text", "Bandit 보안 이슈"),
                    description=f"[{test_id}] {test_name}: {finding.get('more_info', '')}",
                    severity=severity,
                    file_path=finding.get("filename", ""),
                    line_start=finding.get("line_number", 1),
                    line_end=line_end,
                    code_snippet=code_snippet,
                    source="bandit",
                    confidence=confidence,
                )
                results.append(result)

            except Exception as e:
                logger.warning(f"Bandit 결과 항목 파싱 실패: {e}")
                continue

        logger.info(f"Bandit 분석 완료: {len(results)}개 이슈 발견")
        return results
