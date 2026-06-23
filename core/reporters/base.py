"""리포터 공통 인터페이스."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from anshim.core.analyzers.hybrid import HybridScanResult
from anshim.core.compliance.mapper import MappedResult


@dataclass
class ComplianceStat:
    """컴플라이언스별 통계."""

    compliance_type: str
    total: int
    by_severity: dict = field(default_factory=dict)


@dataclass
class ReportData:
    """리포트 생성을 위한 정규화 데이터 모델."""

    scan_id: str
    generated_at: str
    target_path: str
    total_files: int
    scanned_files: int
    duration_seconds: float
    model_used: Optional[str]
    compliance_types: list
    llm_enabled: bool

    # 심각도별 통계
    total_issues: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    false_positives_removed: int

    # 컴플라이언스 통계
    compliance_stats: list  # list[ComplianceStat]

    # 취약점 목록
    results: list  # list[MappedResult]

    @classmethod
    def from_hybrid_result(cls, result: HybridScanResult) -> "ReportData":
        """HybridScanResult에서 ReportData 생성."""
        compliance_stats = []
        for comp_type, stats in result.compliance_summary.items():
            if stats.get("total", 0) > 0:
                compliance_stats.append(
                    ComplianceStat(
                        compliance_type=comp_type,
                        total=stats["total"],
                        by_severity=stats.get("by_severity", {}),
                    )
                )

        return cls(
            scan_id=result.scan_id,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_path=result.target_path,
            total_files=result.total_files,
            scanned_files=result.scanned_files,
            duration_seconds=result.duration_seconds,
            model_used=result.model_used,
            compliance_types=result.compliance_types,
            llm_enabled=result.llm_enabled,
            total_issues=result.total_issues,
            critical_count=result.critical_count,
            high_count=result.high_count,
            medium_count=result.medium_count,
            low_count=result.low_count,
            false_positives_removed=result.false_positives_removed,
            compliance_stats=compliance_stats,
            results=result.results,
        )


class BaseReporter(ABC):
    """리포터 공통 인터페이스."""

    @abstractmethod
    def generate(self, scan_result: HybridScanResult, output_path: Path) -> Path:
        """리포트 파일 생성.

        Args:
            scan_result: 하이브리드 스캔 결과.
            output_path: 출력 경로 (파일 또는 디렉토리).

        Returns:
            생성된 파일 경로.
        """
