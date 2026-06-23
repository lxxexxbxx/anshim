# anshim/core/analyzers/hybrid.py
"""하이브리드 분석기.

규칙 기반 분석과 LLM 분석을 통합하고 컴플라이언스 매핑을 수행합니다.
"""

import logging
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, Field

from anshim.core.analyzers.llm_analyzer import LLMAnalyzer
from anshim.core.analyzers.models import AnalysisResult, ScanSummary
from anshim.core.analyzers.rule_based import RuleBasedAnalyzer
from anshim.core.compliance import ComplianceMapper, MappedResult
from anshim.core.models import OllamaClient

logger = logging.getLogger(__name__)

# 지원 파일 확장자
SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
}


class HybridScanResult(BaseModel):
    """하이브리드 스캔 결과.

    규칙 기반 + LLM 분석 + 컴플라이언스 매핑이 모두 포함된 최종 결과.
    """

    scan_id: str = Field(..., description="스캔 고유 ID (UUID)")
    target_path: str = Field(..., description="스캔 대상 경로")
    total_files: int = Field(default=0, ge=0, description="전체 파일 수")
    scanned_files: int = Field(default=0, ge=0, description="스캔된 파일 수")
    duration_seconds: float = Field(default=0.0, ge=0, description="소요 시간 (초)")

    # 분석 설정
    model_used: str | None = Field(default=None, description="사용된 LLM 모델")
    compliance_types: list[str] = Field(default_factory=list, description="적용된 컴플라이언스")
    llm_enabled: bool = Field(default=False, description="LLM 분석 수행 여부")

    # 결과
    results: list[MappedResult] = Field(
        default_factory=list,
        description="컴플라이언스 매핑된 결과 목록",
    )

    # 통계
    total_issues: int = Field(default=0, description="전체 이슈 수")
    critical_count: int = Field(default=0, description="Critical 이슈 수")
    high_count: int = Field(default=0, description="High 이슈 수")
    medium_count: int = Field(default=0, description="Medium 이슈 수")
    low_count: int = Field(default=0, description="Low 이슈 수")
    false_positives_removed: int = Field(default=0, description="제거된 FP 수")

    # 컴플라이언스별 통계
    compliance_summary: dict = Field(default_factory=dict, description="컴플라이언스별 통계")

    @classmethod
    def from_scan_summary(
        cls,
        scan_id: str,
        summary: ScanSummary,
        mapped_results: list[MappedResult],
        model_used: str | None,
        compliance_types: list[str],
        llm_enabled: bool,
        false_positives_removed: int,
        compliance_summary: dict,
    ) -> "HybridScanResult":
        """ScanSummary에서 HybridScanResult 생성."""
        # 심각도별 카운트 계산
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for result in mapped_results:
            sev = result.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return cls(
            scan_id=scan_id,
            target_path=summary.target_path,
            total_files=summary.total_files,
            scanned_files=summary.scanned_files,
            duration_seconds=summary.duration_seconds,
            model_used=model_used,
            compliance_types=compliance_types,
            llm_enabled=llm_enabled,
            results=mapped_results,
            total_issues=len(mapped_results),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            false_positives_removed=false_positives_removed,
            compliance_summary=compliance_summary,
        )

    def filter_by_severity(self, severity: str) -> "HybridScanResult":
        """심각도로 필터링된 결과 반환."""
        filtered = [r for r in self.results if r.severity.lower() == severity.lower()]

        # 새 결과 생성
        result = self.model_copy()
        result.results = filtered
        result.total_issues = len(filtered)

        # 심각도별 카운트 재계산
        result.critical_count = sum(1 for r in filtered if r.severity.lower() == "critical")
        result.high_count = sum(1 for r in filtered if r.severity.lower() == "high")
        result.medium_count = sum(1 for r in filtered if r.severity.lower() == "medium")
        result.low_count = sum(1 for r in filtered if r.severity.lower() == "low")

        return result


class HybridAnalyzer:
    """하이브리드 분석기.

    규칙 기반 분석 → LLM 심층 분석 → 컴플라이언스 매핑 파이프라인을 관리합니다.
    """

    def __init__(
        self,
        model: str | None = None,
        compliance_types: list[str] | None = None,
        rules_dir: Path | None = None,
        ollama_client: OllamaClient | None = None,
    ):
        """HybridAnalyzer 초기화.

        Args:
            model: LLM 모델명. None이면 기본 모델 사용.
            compliance_types: 컴플라이언스 유형 목록.
            rules_dir: 룰셋 디렉토리 경로.
            ollama_client: Ollama 클라이언트.
        """
        self.model = model or "exaone3.5:7.8b"
        self.compliance_types = compliance_types or ["isms-p"]
        self.rules_dir = rules_dir

        # 분석기 초기화
        self._rule_analyzer = RuleBasedAnalyzer()
        self._ollama_client = ollama_client or OllamaClient()
        self._llm_analyzer: LLMAnalyzer | None = None
        self._compliance_mapper: ComplianceMapper | None = None

        # 상태
        self._llm_available: bool | None = None

    @property
    def llm_available(self) -> bool:
        """LLM 분석 가능 여부."""
        if self._llm_available is None:
            self._llm_available = self._ollama_client.is_running()
        return self._llm_available

    def analyze(
        self,
        target: Path,
        skip_llm: bool = False,
        llm_timeout: int = 90,
        progress_callback: Callable[..., None] | None = None,
    ) -> HybridScanResult:
        """하이브리드 분석 실행.

        Args:
            target: 분석 대상 경로.
            skip_llm: LLM 분석 스킵 여부.
            llm_timeout: LLM 요청 타임아웃 (초).
            progress_callback: 진행 상황 콜백 (단계명, 진행률).

        Returns:
            하이브리드 스캔 결과.
        """
        start_time = time.time()
        scan_id = str(uuid.uuid4())[:8]  # 짧은 ID 사용

        logger.info(
            "하이브리드 분석 시작 [%s]: %s (compliance: %s)",
            scan_id,
            target,
            ", ".join(self.compliance_types),
        )

        # 1. 규칙 기반 분석
        if progress_callback:
            progress_callback("규칙 기반 분석", 0.1)

        rule_summary = self._run_rule_based_analysis(target)
        logger.info(
            "[%s] 규칙 기반 분석 완료: %d개 이슈",
            scan_id,
            len(rule_summary.results),
        )

        # 2. LLM 분석 (선택적)
        llm_enabled = False
        false_positives_removed = 0
        analyzed_results = rule_summary.results

        if not skip_llm and self.llm_available and rule_summary.results:
            if progress_callback:
                progress_callback("LLM 심층 분석", 0.4)

            analyzed_results, fp_count = self._run_llm_analysis(
                rule_summary.results,
                timeout=llm_timeout,
            )
            llm_enabled = True
            false_positives_removed = fp_count
            logger.info(
                "[%s] LLM 분석 완료: %d개 이슈 (FP 제거: %d)",
                scan_id,
                len(analyzed_results),
                fp_count,
            )
        elif skip_llm:
            logger.info("[%s] LLM 분석 스킵 (--rule-only)", scan_id)
        elif not self.llm_available:
            logger.info("[%s] LLM 분석 스킵 (Ollama 미실행)", scan_id)

        # 3. 컴플라이언스 매핑
        if progress_callback:
            progress_callback("컴플라이언스 매핑", 0.8)

        mapped_results = self._run_compliance_mapping(analyzed_results)
        logger.info(
            "[%s] 컴플라이언스 매핑 완료: %d개 결과",
            scan_id,
            len(mapped_results),
        )

        # 4. 통계 계산
        compliance_summary = {}
        if self._compliance_mapper:
            compliance_summary = self._compliance_mapper.get_compliance_summary(
                mapped_results
            )

        # 5. 최종 결과 생성
        duration = time.time() - start_time
        rule_summary.duration_seconds = duration

        if progress_callback:
            progress_callback("완료", 1.0)

        result = HybridScanResult.from_scan_summary(
            scan_id=scan_id,
            summary=rule_summary,
            mapped_results=mapped_results,
            model_used=self.model if llm_enabled else None,
            compliance_types=self.compliance_types,
            llm_enabled=llm_enabled,
            false_positives_removed=false_positives_removed,
            compliance_summary=compliance_summary,
        )

        logger.info(
            "[%s] 하이브리드 분석 완료: %.2f초, %d개 이슈",
            scan_id,
            duration,
            result.total_issues,
        )

        return result

    def _run_rule_based_analysis(self, target: Path) -> ScanSummary:
        """규칙 기반 분석 실행.

        Args:
            target: 분석 대상 경로.

        Returns:
            스캔 요약 결과.
        """
        return self._rule_analyzer.analyze(target)

    def _run_llm_analysis(
        self,
        results: list[AnalysisResult],
        timeout: int = 90,
    ) -> tuple[list[AnalysisResult], int]:
        """LLM 분석 실행.

        Args:
            results: 규칙 기반 분석 결과.
            timeout: 개별 요청 타임아웃.

        Returns:
            (분석된 결과 목록, 제거된 FP 수) 튜플.
        """
        if self._llm_analyzer is None:
            self._llm_analyzer = LLMAnalyzer(
                model=self.model,
                ollama_client=self._ollama_client,
            )

        # 배치 분석
        analyzed = self._llm_analyzer.analyze_batch(
            results,
            max_concurrent=2,
            timeout=timeout,
        )

        # False Positive 필터링
        filtered = self._llm_analyzer.filter_false_positives(analyzed)
        fp_count = len(analyzed) - len(filtered)

        return filtered, fp_count

    def _run_compliance_mapping(
        self,
        results: list[AnalysisResult],
    ) -> list[MappedResult]:
        """컴플라이언스 매핑 실행.

        Args:
            results: 분석 결과 목록.

        Returns:
            매핑된 결과 목록.
        """
        if self._compliance_mapper is None:
            self._compliance_mapper = ComplianceMapper(
                rules_dir=self.rules_dir,
                compliance_types=self.compliance_types,
            )

        return self._compliance_mapper.map_results(results)

    def get_status(self) -> dict:
        """분석기 상태 확인.

        Returns:
            분석기별 상태 딕셔너리.
        """
        rule_status = self._rule_analyzer.get_status()
        return {
            **rule_status,
            "ollama": self.llm_available,
            "model": self.model,
            "compliance_types": self.compliance_types,
        }
