# anshim/core/analyzers/models.py
"""분석 결과를 위한 공통 모델 정의."""


from pydantic import BaseModel, ConfigDict, Field


class AnalysisResult(BaseModel):
    """개별 취약점 분석 결과 모델.

    Semgrep, Bandit 등 다양한 분석기의 결과를 통일된 형식으로 표현.
    """

    model_config = ConfigDict(extra="allow")

    rule_id: str = Field(..., description="규칙 ID (예: python.cryptography.security.insecure-hash-md5)")
    title: str = Field(..., description="취약점 제목")
    description: str = Field(default="", description="취약점 상세 설명")
    severity: str = Field(..., description="심각도: critical, high, medium, low")
    file_path: str = Field(..., description="취약점 발견 파일 경로")
    line_start: int = Field(..., ge=1, description="시작 라인 번호")
    line_end: int | None = Field(default=None, description="종료 라인 번호")
    code_snippet: str | None = Field(default=None, description="취약한 코드 스니펫")
    source: str = Field(..., description="분석기 출처: semgrep, bandit")
    confidence: str = Field(default="medium", description="신뢰도: high, medium, low")

    def unique_key(self) -> str:
        """중복 제거를 위한 고유 키 생성.

        Returns:
            파일 경로와 시작 라인을 조합한 문자열.
        """
        return f"{self.file_path}:{self.line_start}:{self.rule_id}"


class ScanSummary(BaseModel):
    """스캔 전체 요약 모델.

    스캔 세션 전체의 메타데이터와 발견된 모든 취약점을 포함.
    """

    target_path: str = Field(..., description="스캔 대상 경로")
    total_files: int = Field(default=0, ge=0, description="전체 파일 수")
    scanned_files: int = Field(default=0, ge=0, description="스캔된 파일 수")
    results: list[AnalysisResult] = Field(default_factory=list, description="분석 결과 목록")
    duration_seconds: float = Field(default=0.0, ge=0, description="스캔 소요 시간 (초)")

    @property
    def total_issues(self) -> int:
        """발견된 전체 이슈 수."""
        return len(self.results)

    @property
    def critical_count(self) -> int:
        """심각도 critical 이슈 수."""
        return sum(1 for r in self.results if r.severity == "critical")

    @property
    def high_count(self) -> int:
        """심각도 high 이슈 수."""
        return sum(1 for r in self.results if r.severity == "high")

    @property
    def medium_count(self) -> int:
        """심각도 medium 이슈 수."""
        return sum(1 for r in self.results if r.severity == "medium")

    @property
    def low_count(self) -> int:
        """심각도 low 이슈 수."""
        return sum(1 for r in self.results if r.severity == "low")

    def by_severity(self) -> dict[str, list[AnalysisResult]]:
        """심각도별로 결과 분류.

        Returns:
            심각도를 키로 하는 결과 딕셔너리.
        """
        result: dict[str, list[AnalysisResult]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }
        for r in self.results:
            if r.severity in result:
                result[r.severity].append(r)
            else:
                result["low"].append(r)  # 알 수 없는 심각도는 low로 분류
        return result

    def by_file(self) -> dict[str, list[AnalysisResult]]:
        """파일별로 결과 분류.

        Returns:
            파일 경로를 키로 하는 결과 딕셔너리.
        """
        result: dict[str, list[AnalysisResult]] = {}
        for r in self.results:
            if r.file_path not in result:
                result[r.file_path] = []
            result[r.file_path].append(r)
        return result
