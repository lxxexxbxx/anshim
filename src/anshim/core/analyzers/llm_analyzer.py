# anshim/core/analyzers/llm_analyzer.py
"""LLM 기반 보안 코드 분석기.

규칙 기반 분석 결과를 LLM으로 심층 분석하여 False Positive를 제거하고,
공격 시나리오 및 수정 제안을 생성합니다.
"""

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from anshim.core.analyzers.models import AnalysisResult
from anshim.core.models.ollama_client import OllamaClient, OllamaNotRunningError

logger = logging.getLogger(__name__)

# 프롬프트 템플릿 디렉토리
PROMPT_DIR = Path(__file__).parent.parent / "prompts" / "ko"


class LLMAnalyzer:
    """LLM 기반 보안 분석기.

    규칙 기반 분석 결과를 LLM으로 2차 검증하고,
    공격 시나리오와 수정 제안을 한국어로 생성합니다.

    Attributes:
        model: 사용할 Ollama 모델 이름.
        ollama_client: Ollama 클라이언트.
        template_env: Jinja2 템플릿 환경.
    """

    def __init__(
        self,
        model: str,
        ollama_client: OllamaClient | None = None,
    ):
        """LLMAnalyzer 초기화.

        Args:
            model: 사용할 모델 이름 (예: exaone3.5:7.8b).
            ollama_client: Ollama 클라이언트. None이면 기본값 생성.
        """
        self.model = model
        self.ollama_client = ollama_client or OllamaClient()
        self._ollama_available: bool | None = None

        # Jinja2 템플릿 환경 설정
        self.template_env = Environment(
            loader=FileSystemLoader(str(PROMPT_DIR)),
            autoescape=False,  # noqa: S701
        )

    def is_available(self) -> bool:
        """LLM 분석 가능 여부 확인.

        Returns:
            Ollama가 실행 중이면 True, 아니면 False.
        """
        if self._ollama_available is None:
            self._ollama_available = self.ollama_client.is_running()
        return self._ollama_available

    def analyze_vulnerability(
        self,
        result: AnalysisResult,
        timeout: int = 60,
    ) -> AnalysisResult:
        """취약점 1개를 LLM으로 심층 분석.

        Args:
            result: 규칙 기반 분석 결과.
            timeout: LLM 요청 타임아웃 (초).

        Returns:
            LLM 분석이 추가된 AnalysisResult.
            Ollama 미실행 시 원본 그대로 반환.
        """
        if not self.is_available():
            logger.warning("Ollama 미실행으로 LLM 분석 스킵")
            return result

        try:
            # 취약점 분석 프롬프트 렌더링
            analysis_prompt = self._render_template(
                "vulnerability_analysis.jinja2",
                result,
            )

            # LLM 응답 생성
            analysis_response = self.ollama_client.generate(
                model=self.model,
                prompt=analysis_prompt,
                timeout=timeout,
            )

            # JSON 파싱
            analysis_data = self._parse_json_response(analysis_response)

            if analysis_data:
                # False Positive 여부 업데이트
                is_fp = analysis_data.get("is_false_positive", False)

                # 결과 복사 후 LLM 분석 결과 추가
                result_dict = result.model_dump()
                result_dict["llm_analysis"] = analysis_data.get("analysis", "")
                result_dict["is_false_positive"] = is_fp
                result_dict["severity_adjusted"] = analysis_data.get(
                    "severity_adjusted", result.severity
                )
                result_dict["isms_relevance"] = analysis_data.get("isms_relevance", "")

                # False Positive가 아닌 경우에만 공격 시나리오와 수정 제안 생성
                if not is_fp:
                    # 공격 시나리오 생성
                    attack_data = self._generate_attack_scenario(result, timeout)
                    if attack_data:
                        result_dict["attack_scenario"] = attack_data

                    # 수정 제안 생성
                    fix_data = self._generate_fix_suggestion(result, timeout)
                    if fix_data:
                        result_dict["remediation"] = fix_data

                return AnalysisResult(**result_dict)

        except OllamaNotRunningError:
            logger.warning("Ollama 연결 끊김, 원본 결과 반환")
            self._ollama_available = False
        except Exception as e:
            logger.error("LLM 분석 실패 (%s): %s", result.rule_id, e)

        return result

    def _generate_attack_scenario(
        self,
        result: AnalysisResult,
        timeout: int = 60,
    ) -> dict[str, Any] | None:
        """공격 시나리오 생성.

        Args:
            result: 분석 결과.
            timeout: 타임아웃 (초).

        Returns:
            공격 시나리오 딕셔너리 또는 None.
        """
        try:
            prompt = self._render_template("attack_scenario.jinja2", result)
            response = self.ollama_client.generate(
                model=self.model,
                prompt=prompt,
                timeout=timeout,
            )
            return self._parse_json_response(response)
        except Exception as e:
            logger.debug("공격 시나리오 생성 실패: %s", e)
            return None

    def _generate_fix_suggestion(
        self,
        result: AnalysisResult,
        timeout: int = 60,
    ) -> dict[str, Any] | None:
        """수정 제안 생성.

        Args:
            result: 분석 결과.
            timeout: 타임아웃 (초).

        Returns:
            수정 제안 딕셔너리 또는 None.
        """
        try:
            prompt = self._render_template("fix_suggestion.jinja2", result)
            response = self.ollama_client.generate(
                model=self.model,
                prompt=prompt,
                timeout=timeout,
            )
            return self._parse_json_response(response)
        except Exception as e:
            logger.debug("수정 제안 생성 실패: %s", e)
            return None

    def analyze_batch(
        self,
        results: list[AnalysisResult],
        max_concurrent: int = 3,
        timeout: int = 60,
    ) -> list[AnalysisResult]:
        """배치로 여러 취약점 분석.

        Args:
            results: 분석할 결과 목록.
            max_concurrent: 동시 실행 수.
            timeout: 개별 요청 타임아웃 (초).

        Returns:
            LLM 분석이 추가된 결과 목록.
            Ollama 미실행 시 원본 그대로 반환.
        """
        if not self.is_available():
            logger.warning("Ollama 미실행으로 LLM 배치 분석 스킵")
            return results

        if not results:
            return results

        analyzed_results: list[AnalysisResult] = []

        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            # 작업 제출
            future_to_result = {
                executor.submit(
                    self.analyze_vulnerability, result, timeout
                ): result
                for result in results
            }

            # 결과 수집
            for future in as_completed(future_to_result):
                original = future_to_result[future]
                try:
                    analyzed = future.result()
                    analyzed_results.append(analyzed)
                except Exception as e:
                    logger.error("배치 분석 실패 (%s): %s", original.rule_id, e)
                    analyzed_results.append(original)

        # 원본 순서 유지 (file_path + line_start 기준)
        result_order = {r.unique_key(): i for i, r in enumerate(results)}
        analyzed_results.sort(key=lambda r: result_order.get(r.unique_key(), 999))

        return analyzed_results

    def filter_false_positives(
        self,
        results: list[AnalysisResult],
    ) -> list[AnalysisResult]:
        """False Positive로 판단된 결과 제거.

        Args:
            results: LLM 분석이 완료된 결과 목록.

        Returns:
            is_false_positive=True인 결과가 제거된 목록.
        """
        return [
            r for r in results
            if not getattr(r, "is_false_positive", False)
        ]

    def _render_template(
        self,
        template_name: str,
        result: AnalysisResult,
    ) -> str:
        """Jinja2 템플릿 렌더링.

        Args:
            template_name: 템플릿 파일명.
            result: 템플릿에 전달할 AnalysisResult.

        Returns:
            렌더링된 프롬프트 문자열.
        """
        template = self.template_env.get_template(template_name)
        return template.render(
            rule_id=result.rule_id,
            title=result.title,
            description=result.description,
            severity=result.severity,
            file_path=result.file_path,
            line_start=result.line_start,
            line_end=result.line_end,
            code_snippet=result.code_snippet or "",
            source=result.source,
            confidence=result.confidence,
            language=self._detect_language(result.file_path),
        )

    def _parse_json_response(self, response: str) -> dict[str, Any] | None:
        """LLM 응답에서 JSON 추출.

        Args:
            response: LLM 응답 문자열.

        Returns:
            파싱된 딕셔너리 또는 None.
        """
        if not response:
            return None

        # JSON 블록 추출 시도 (```json ... ```)
        json_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", response)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # 전체 응답이 JSON인 경우
        try:
            return json.loads(response.strip())
        except json.JSONDecodeError:
            pass

        # { ... } 패턴 추출
        brace_match = re.search(r"\{[\s\S]*\}", response)
        if brace_match:
            try:
                return json.loads(brace_match.group())
            except json.JSONDecodeError:
                pass

        logger.warning("JSON 파싱 실패: %s...", response[:100])
        return None

    @staticmethod
    def _detect_language(file_path: str) -> str:
        """파일 경로에서 프로그래밍 언어 추론.

        Args:
            file_path: 파일 경로.

        Returns:
            언어 이름 (python, javascript, java, unknown).
        """
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
            ".rb": "ruby",
            ".php": "php",
            ".c": "c",
            ".cpp": "cpp",
            ".h": "c",
            ".hpp": "cpp",
        }

        path = Path(file_path)
        return ext_map.get(path.suffix.lower(), "unknown")
