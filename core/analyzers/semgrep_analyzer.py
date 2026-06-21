# anshim/core/analyzers/semgrep_analyzer.py
"""Semgrep 기반 정적 분석기 래퍼."""

import json
import logging
import shutil
import subprocess
from pathlib import Path

from .models import AnalysisResult

logger = logging.getLogger(__name__)

# 지원 언어와 확장자 매핑
LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".mjs"],
    "typescript": [".ts", ".tsx"],
    "java": [".java"],
}

# Semgrep 심각도 매핑
SEVERITY_MAP: dict[str, str] = {
    "ERROR": "critical",
    "WARNING": "high",
    "INFO": "medium",
    "EXPERIMENT": "low",
}


class SemgrepAnalyzer:
    """Semgrep를 이용한 정적 코드 분석기.

    Semgrep CLI를 subprocess로 실행하여 코드를 분석하고,
    결과를 AnalysisResult 형식으로 변환합니다.
    """

    def __init__(self) -> None:
        """SemgrepAnalyzer 초기화."""
        self._semgrep_path: str | None = shutil.which("semgrep")

    def is_available(self) -> bool:
        """Semgrep 설치 여부 확인.

        Returns:
            Semgrep가 설치되어 있으면 True.
        """
        return self._semgrep_path is not None

    def analyze(
        self,
        target: Path,
        languages: list[str] | None = None,
    ) -> list[AnalysisResult]:
        """대상 경로를 Semgrep으로 분석.

        Args:
            target: 분석 대상 파일 또는 디렉토리 경로.
            languages: 분석할 언어 목록. None이면 모든 지원 언어.

        Returns:
            분석 결과 목록.
        """
        if not self.is_available():
            logger.warning("Semgrep이 설치되어 있지 않습니다. 'pip install semgrep'로 설치하세요.")
            return []

        if not target.exists():
            logger.warning(f"대상 경로가 존재하지 않습니다: {target}")
            return []

        # 언어 필터 구성
        if languages is None:
            languages = list(LANGUAGE_EXTENSIONS.keys())

        try:
            # Semgrep 명령 구성
            # 다중 언어 지원을 위해 각 언어별 룰셋 추가
            configs = []
            for lang in languages:
                if lang == "python":
                    configs.extend(["--config", "p/python"])
                elif lang in ("javascript", "typescript"):
                    configs.extend(["--config", "p/javascript"])
                elif lang == "java":
                    configs.extend(["--config", "p/java"])

            # 기본값으로 p/default 추가 (언어 무관 규칙)
            if not configs:
                configs = ["--config", "p/default"]

            cmd = [
                "semgrep",
                "--json",
                *configs,
                "--no-git-ignore",  # .gitignore 무시 (테스트 코드도 분석)
                "--metrics", "off",  # 메트릭 전송 비활성화 (프라이버시)
                str(target),
            ]

            logger.debug(f"Semgrep 실행: {' '.join(cmd)}")

            # Semgrep 실행
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5분 타임아웃
            )

            # JSON 결과 파싱
            if result.stdout:
                return self._parse_output(result.stdout, languages)

            if result.returncode != 0 and result.stderr:
                # Semgrep은 경고도 stderr로 출력하므로 로그만 남김
                logger.debug(f"Semgrep stderr: {result.stderr}")

            return []

        except subprocess.TimeoutExpired:
            logger.error("Semgrep 실행 시간이 초과되었습니다 (5분).")
            return []
        except FileNotFoundError:
            logger.error("Semgrep 실행 파일을 찾을 수 없습니다.")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Semgrep 출력 JSON 파싱 실패: {e}")
            return []
        except Exception as e:
            logger.error(f"Semgrep 분석 중 오류 발생: {e}")
            return []

    def _parse_output(
        self,
        output: str,
        languages: list[str],
    ) -> list[AnalysisResult]:
        """Semgrep JSON 출력을 AnalysisResult 목록으로 변환.

        Args:
            output: Semgrep JSON 출력 문자열.
            languages: 필터링할 언어 목록.

        Returns:
            변환된 AnalysisResult 목록.
        """
        results: list[AnalysisResult] = []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            logger.error("Semgrep 출력을 JSON으로 파싱할 수 없습니다.")
            return []

        # 결과 목록 추출
        findings = data.get("results", [])

        # 허용된 확장자 목록 생성
        allowed_extensions: set[str] = set()
        for lang in languages:
            if lang in LANGUAGE_EXTENSIONS:
                allowed_extensions.update(LANGUAGE_EXTENSIONS[lang])

        for finding in findings:
            try:
                file_path = finding.get("path", "")

                # 언어 필터링
                file_ext = Path(file_path).suffix.lower()
                if allowed_extensions and file_ext not in allowed_extensions:
                    continue

                # 심각도 매핑
                raw_severity = finding.get("extra", {}).get("severity", "INFO")
                severity = SEVERITY_MAP.get(raw_severity, "medium")

                # 코드 스니펫 추출
                code_snippet = None
                if "extra" in finding and "lines" in finding["extra"]:
                    code_snippet = finding["extra"]["lines"]

                result = AnalysisResult(
                    rule_id=finding.get("check_id", "unknown"),
                    title=finding.get("extra", {}).get("message", "Semgrep 규칙 위반"),
                    description=finding.get("extra", {}).get("metadata", {}).get("message", ""),
                    severity=severity,
                    file_path=file_path,
                    line_start=finding.get("start", {}).get("line", 1),
                    line_end=finding.get("end", {}).get("line"),
                    code_snippet=code_snippet,
                    source="semgrep",
                    confidence=finding.get("extra", {}).get("metadata", {}).get("confidence", "medium").lower(),
                )
                results.append(result)

            except Exception as e:
                logger.warning(f"Semgrep 결과 항목 파싱 실패: {e}")
                continue

        logger.info(f"Semgrep 분석 완료: {len(results)}개 이슈 발견")
        return results
