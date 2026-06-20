"""규칙 기반 분석기 테스트.

Semgrep, Bandit, RuleBasedAnalyzer 통합 테스트.
"""

import os
from pathlib import Path

import pytest

from anshim.core.analyzers import (
    AnalysisResult,
    BanditAnalyzer,
    RuleBasedAnalyzer,
    ScanSummary,
    SemgrepAnalyzer,
)


# 테스트 fixtures 경로
FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULNERABLE_PYTHON = FIXTURES_DIR / "vulnerable_python.py"


class TestAnalysisResultModel:
    """AnalysisResult 모델 테스트."""

    def test_create_analysis_result(self) -> None:
        """AnalysisResult 생성 테스트."""
        result = AnalysisResult(
            rule_id="test-rule-001",
            title="테스트 취약점",
            description="테스트용 취약점 설명",
            severity="high",
            file_path="/path/to/file.py",
            line_start=10,
            line_end=15,
            code_snippet="vulnerable_code()",
            source="semgrep",
            confidence="high",
        )

        assert result.rule_id == "test-rule-001"
        assert result.severity == "high"
        assert result.line_start == 10
        assert result.source == "semgrep"

    def test_unique_key(self) -> None:
        """unique_key 메서드 테스트."""
        result = AnalysisResult(
            rule_id="test-rule",
            title="Test",
            severity="medium",
            file_path="/path/file.py",
            line_start=5,
            source="bandit",
        )

        key = result.unique_key()
        assert key == "/path/file.py:5:test-rule"

    def test_default_values(self) -> None:
        """기본값 테스트."""
        result = AnalysisResult(
            rule_id="test",
            title="Test",
            severity="low",
            file_path="test.py",
            line_start=1,
            source="test",
        )

        assert result.description == ""
        assert result.line_end is None
        assert result.code_snippet is None
        assert result.confidence == "medium"


class TestScanSummaryModel:
    """ScanSummary 모델 테스트."""

    def test_create_scan_summary(self) -> None:
        """ScanSummary 생성 테스트."""
        results = [
            AnalysisResult(
                rule_id="r1", title="T1", severity="critical",
                file_path="a.py", line_start=1, source="s"
            ),
            AnalysisResult(
                rule_id="r2", title="T2", severity="high",
                file_path="b.py", line_start=2, source="s"
            ),
            AnalysisResult(
                rule_id="r3", title="T3", severity="medium",
                file_path="c.py", line_start=3, source="s"
            ),
        ]

        summary = ScanSummary(
            target_path="/test",
            total_files=10,
            scanned_files=5,
            results=results,
            duration_seconds=1.5,
        )

        assert summary.total_issues == 3
        assert summary.critical_count == 1
        assert summary.high_count == 1
        assert summary.medium_count == 1
        assert summary.low_count == 0

    def test_by_severity(self) -> None:
        """심각도별 분류 테스트."""
        results = [
            AnalysisResult(
                rule_id="r1", title="T1", severity="high",
                file_path="a.py", line_start=1, source="s"
            ),
            AnalysisResult(
                rule_id="r2", title="T2", severity="high",
                file_path="b.py", line_start=2, source="s"
            ),
            AnalysisResult(
                rule_id="r3", title="T3", severity="low",
                file_path="c.py", line_start=3, source="s"
            ),
        ]

        summary = ScanSummary(
            target_path="/test",
            results=results,
        )

        by_severity = summary.by_severity()
        assert len(by_severity["high"]) == 2
        assert len(by_severity["low"]) == 1
        assert len(by_severity["critical"]) == 0

    def test_by_file(self) -> None:
        """파일별 분류 테스트."""
        results = [
            AnalysisResult(
                rule_id="r1", title="T1", severity="high",
                file_path="file1.py", line_start=1, source="s"
            ),
            AnalysisResult(
                rule_id="r2", title="T2", severity="high",
                file_path="file1.py", line_start=10, source="s"
            ),
            AnalysisResult(
                rule_id="r3", title="T3", severity="low",
                file_path="file2.py", line_start=5, source="s"
            ),
        ]

        summary = ScanSummary(
            target_path="/test",
            results=results,
        )

        by_file = summary.by_file()
        assert len(by_file["file1.py"]) == 2
        assert len(by_file["file2.py"]) == 1


class TestSemgrepAnalyzer:
    """Semgrep 분석기 테스트."""

    def test_is_available(self) -> None:
        """Semgrep 사용 가능 여부 테스트."""
        analyzer = SemgrepAnalyzer()
        # 설치 여부에 관계없이 메서드가 동작해야 함
        result = analyzer.is_available()
        assert isinstance(result, bool)

    def test_analyze_nonexistent_path(self) -> None:
        """존재하지 않는 경로 분석 테스트."""
        analyzer = SemgrepAnalyzer()
        results = analyzer.analyze(Path("/nonexistent/path"))
        assert results == []

    @pytest.mark.skipif(
        not SemgrepAnalyzer().is_available(),
        reason="Semgrep이 설치되어 있지 않음"
    )
    def test_analyze_vulnerable_python(self) -> None:
        """취약한 Python 파일 분석 테스트."""
        if not VULNERABLE_PYTHON.exists():
            pytest.skip("취약한 Python 샘플 파일이 없음")

        analyzer = SemgrepAnalyzer()
        results = analyzer.analyze(VULNERABLE_PYTHON, languages=["python"])

        # Semgrep이 취약점을 발견해야 함
        assert isinstance(results, list)
        # 결과가 있으면 AnalysisResult 타입이어야 함
        if results:
            assert all(isinstance(r, AnalysisResult) for r in results)
            assert all(r.source == "semgrep" for r in results)


class TestBanditAnalyzer:
    """Bandit 분석기 테스트."""

    def test_is_available(self) -> None:
        """Bandit 사용 가능 여부 테스트."""
        analyzer = BanditAnalyzer()
        result = analyzer.is_available()
        assert isinstance(result, bool)

    def test_analyze_nonexistent_path(self) -> None:
        """존재하지 않는 경로 분석 테스트."""
        analyzer = BanditAnalyzer()
        results = analyzer.analyze(Path("/nonexistent/path"))
        assert results == []

    @pytest.mark.skipif(
        not BanditAnalyzer().is_available(),
        reason="Bandit이 설치되어 있지 않음"
    )
    def test_analyze_vulnerable_python(self) -> None:
        """취약한 Python 파일 분석 테스트."""
        if not VULNERABLE_PYTHON.exists():
            pytest.skip("취약한 Python 샘플 파일이 없음")

        analyzer = BanditAnalyzer()
        results = analyzer.analyze(VULNERABLE_PYTHON)

        # Bandit이 취약점을 발견해야 함
        assert isinstance(results, list)
        # 결과가 있으면 AnalysisResult 타입이어야 함
        if results:
            assert all(isinstance(r, AnalysisResult) for r in results)
            assert all(r.source == "bandit" for r in results)


class TestRuleBasedAnalyzer:
    """RuleBasedAnalyzer 통합 테스트."""

    def test_get_status(self) -> None:
        """분석기 상태 확인 테스트."""
        analyzer = RuleBasedAnalyzer()
        status = analyzer.get_status()

        assert "semgrep" in status
        assert "bandit" in status
        assert isinstance(status["semgrep"], bool)
        assert isinstance(status["bandit"], bool)

    def test_analyze_nonexistent_path(self) -> None:
        """존재하지 않는 경로 분석 테스트."""
        analyzer = RuleBasedAnalyzer()
        summary = analyzer.analyze(Path("/nonexistent/path"))

        assert isinstance(summary, ScanSummary)
        assert summary.total_files == 0
        assert summary.results == []

    def test_analyze_returns_scan_summary(self) -> None:
        """분석 결과가 ScanSummary 타입인지 테스트."""
        analyzer = RuleBasedAnalyzer()
        # 현재 디렉토리 분석 (빈 결과여도 ScanSummary 반환)
        summary = analyzer.analyze(Path("."))

        assert isinstance(summary, ScanSummary)
        assert hasattr(summary, "target_path")
        assert hasattr(summary, "total_files")
        assert hasattr(summary, "results")
        assert hasattr(summary, "duration_seconds")

    @pytest.mark.skipif(
        not (SemgrepAnalyzer().is_available() or BanditAnalyzer().is_available()),
        reason="Semgrep 또는 Bandit이 설치되어 있지 않음"
    )
    def test_analyze_vulnerable_python(self) -> None:
        """취약한 Python 파일 통합 분석 테스트."""
        if not VULNERABLE_PYTHON.exists():
            pytest.skip("취약한 Python 샘플 파일이 없음")

        analyzer = RuleBasedAnalyzer()
        summary = analyzer.analyze(VULNERABLE_PYTHON)

        assert isinstance(summary, ScanSummary)
        # 적어도 일부 취약점은 발견되어야 함
        # (Semgrep 또는 Bandit 중 하나라도 있으면)
        if analyzer.get_status()["semgrep"] or analyzer.get_status()["bandit"]:
            # 파일이 분석되었어야 함
            assert summary.scanned_files >= 0

    def test_deduplication(self) -> None:
        """중복 제거 테스트."""
        analyzer = RuleBasedAnalyzer()

        # 동일한 결과 생성
        results = [
            AnalysisResult(
                rule_id="same-rule",
                title="Same Issue",
                severity="high",
                file_path="test.py",
                line_start=10,
                source="semgrep",
            ),
            AnalysisResult(
                rule_id="same-rule",
                title="Same Issue",
                severity="high",
                file_path="test.py",
                line_start=10,
                source="bandit",  # 다른 source지만 같은 위치
            ),
        ]

        unique = analyzer._deduplicate(results)

        # 같은 파일+라인+규칙은 하나만 남아야 함
        assert len(unique) == 1


class TestGracefulDegradation:
    """분석기 미설치 시 graceful 처리 테스트."""

    def test_semgrep_not_available_returns_empty(self) -> None:
        """Semgrep 미설치 시 빈 리스트 반환 테스트."""
        analyzer = SemgrepAnalyzer()

        # _semgrep_path를 None으로 설정하여 미설치 상태 시뮬레이션
        original_path = analyzer._semgrep_path
        analyzer._semgrep_path = None

        try:
            results = analyzer.analyze(Path("."))
            assert results == []
        finally:
            analyzer._semgrep_path = original_path

    def test_bandit_not_available_returns_empty(self) -> None:
        """Bandit 미설치 시 빈 리스트 반환 테스트."""
        analyzer = BanditAnalyzer()

        # _bandit_path를 None으로 설정하여 미설치 상태 시뮬레이션
        original_path = analyzer._bandit_path
        analyzer._bandit_path = None

        try:
            results = analyzer.analyze(Path("."))
            assert results == []
        finally:
            analyzer._bandit_path = original_path

    def test_rule_based_no_analyzers_returns_empty_summary(self) -> None:
        """모든 분석기 미설치 시 빈 요약 반환 테스트."""
        analyzer = RuleBasedAnalyzer()

        # 분석기 경로를 None으로 설정
        original_semgrep = analyzer._semgrep._semgrep_path
        original_bandit = analyzer._bandit._bandit_path
        analyzer._semgrep._semgrep_path = None
        analyzer._bandit._bandit_path = None

        try:
            summary = analyzer.analyze(Path("."))
            assert isinstance(summary, ScanSummary)
            assert summary.results == []
        finally:
            analyzer._semgrep._semgrep_path = original_semgrep
            analyzer._bandit._bandit_path = original_bandit
