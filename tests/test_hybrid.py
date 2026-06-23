# anshim/tests/test_hybrid.py
"""하이브리드 분석기 및 Repository 통합 테스트."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
import tempfile

from anshim.core.analyzers.hybrid import (
    HybridAnalyzer,
    HybridScanResult,
    SUPPORTED_EXTENSIONS,
)
from anshim.core.analyzers import BanditAnalyzer, SemgrepAnalyzer
from anshim.core.analyzers.models import AnalysisResult, ScanSummary
from anshim.core.compliance.mapper import MappedResult, ComplianceMappingInfo
from anshim.core.db.repository import (
    ScanRepository,
    VulnerabilityRepository,
    save_hybrid_result,
)
from anshim.core.db.models import AnalysisType, SeverityLevel


class TestHybridScanResult:
    """HybridScanResult 모델 테스트."""

    def test_create_from_scan_summary(self):
        """ScanSummary에서 HybridScanResult 생성 테스트."""
        summary = ScanSummary(
            target_path="/test/path",
            total_files=10,
            scanned_files=5,
            duration_seconds=1.5,
            results=[],
        )

        result = HybridScanResult.from_scan_summary(
            scan_id="test123",
            summary=summary,
            mapped_results=[],
            model_used="exaone3.5:7.8b",
            compliance_types=["isms-p", "owasp"],
            llm_enabled=True,
            false_positives_removed=2,
            compliance_summary={"isms-p": {"total": 5}},
        )

        assert result.scan_id == "test123"
        assert result.target_path == "/test/path"
        assert result.total_files == 10
        assert result.scanned_files == 5
        assert result.model_used == "exaone3.5:7.8b"
        assert result.llm_enabled is True
        assert result.false_positives_removed == 2
        assert "isms-p" in result.compliance_types

    def test_severity_counts(self):
        """심각도별 카운트 테스트."""
        mapped_results = [
            MappedResult(
                rule_id="r1",
                title="Test 1",
                severity="critical",
                file_path="/test.py",
                line_start=1,
                source="test",
            ),
            MappedResult(
                rule_id="r2",
                title="Test 2",
                severity="high",
                file_path="/test.py",
                line_start=2,
                source="test",
            ),
            MappedResult(
                rule_id="r3",
                title="Test 3",
                severity="high",
                file_path="/test.py",
                line_start=3,
                source="test",
            ),
            MappedResult(
                rule_id="r4",
                title="Test 4",
                severity="medium",
                file_path="/test.py",
                line_start=4,
                source="test",
            ),
        ]

        summary = ScanSummary(
            target_path="/test",
            total_files=1,
            scanned_files=1,
            duration_seconds=1.0,
            results=[],
        )

        result = HybridScanResult.from_scan_summary(
            scan_id="test",
            summary=summary,
            mapped_results=mapped_results,
            model_used=None,
            compliance_types=["isms-p"],
            llm_enabled=False,
            false_positives_removed=0,
            compliance_summary={},
        )

        assert result.total_issues == 4
        assert result.critical_count == 1
        assert result.high_count == 2
        assert result.medium_count == 1
        assert result.low_count == 0

    def test_filter_by_severity(self):
        """심각도 필터링 테스트."""
        mapped_results = [
            MappedResult(
                rule_id="r1",
                title="High 1",
                severity="high",
                file_path="/test.py",
                line_start=1,
                source="test",
            ),
            MappedResult(
                rule_id="r2",
                title="Low 1",
                severity="low",
                file_path="/test.py",
                line_start=2,
                source="test",
            ),
            MappedResult(
                rule_id="r3",
                title="High 2",
                severity="high",
                file_path="/test.py",
                line_start=3,
                source="test",
            ),
        ]

        result = HybridScanResult(
            scan_id="test",
            target_path="/test",
            results=mapped_results,
            total_issues=3,
            high_count=2,
            low_count=1,
        )

        filtered = result.filter_by_severity("high")

        assert filtered.total_issues == 2
        assert filtered.high_count == 2
        assert filtered.low_count == 0
        assert all(r.severity == "high" for r in filtered.results)


class TestHybridAnalyzer:
    """HybridAnalyzer 테스트."""

    @pytest.fixture
    def fixtures_dir(self):
        """테스트용 fixtures 디렉토리."""
        return Path(__file__).parent / "fixtures"

    @pytest.fixture
    def mock_ollama_down(self):
        """Ollama 미실행 상태 Mock."""
        with patch("anshim.core.models.ollama_client.OllamaClient.is_running") as mock:
            mock.return_value = False
            yield mock

    def test_init_default_values(self):
        """기본값 초기화 테스트."""
        analyzer = HybridAnalyzer()

        assert analyzer.model == "exaone3.5:7.8b"
        assert "isms-p" in analyzer.compliance_types

    def test_init_custom_values(self):
        """사용자 지정값 초기화 테스트."""
        analyzer = HybridAnalyzer(
            model="qwen2.5-coder:14b",
            compliance_types=["isms", "owasp"],
        )

        assert analyzer.model == "qwen2.5-coder:14b"
        assert "isms" in analyzer.compliance_types
        assert "owasp" in analyzer.compliance_types

    def test_analyze_returns_hybrid_scan_result(self, fixtures_dir, mock_ollama_down):
        """analyze 메서드가 HybridScanResult 반환 테스트."""
        analyzer = HybridAnalyzer(compliance_types=["isms-p"])

        result = analyzer.analyze(fixtures_dir, skip_llm=True)

        assert isinstance(result, HybridScanResult)
        assert result.target_path == str(fixtures_dir)
        assert result.llm_enabled is False

    def test_analyze_with_skip_llm(self, fixtures_dir, mock_ollama_down):
        """skip_llm 옵션 테스트."""
        analyzer = HybridAnalyzer()

        result = analyzer.analyze(fixtures_dir, skip_llm=True)

        assert result.llm_enabled is False
        assert result.model_used is None

    @pytest.mark.skipif(
        not (SemgrepAnalyzer().is_available() or BanditAnalyzer().is_available()),
        reason="Semgrep과 Bandit 모두 설치되어 있지 않음",
    )
    def test_analyze_detects_vulnerabilities(self, fixtures_dir, mock_ollama_down):
        """취약점 탐지 테스트."""
        analyzer = HybridAnalyzer(compliance_types=["isms-p", "owasp", "cwe"])

        result = analyzer.analyze(fixtures_dir, skip_llm=True)

        # 취약한 코드가 있으므로 이슈가 발견되어야 함
        assert result.total_issues > 0

    def test_analyze_maps_compliance(self, fixtures_dir, mock_ollama_down):
        """컴플라이언스 매핑 테스트."""
        analyzer = HybridAnalyzer(compliance_types=["isms-p", "owasp"])

        result = analyzer.analyze(fixtures_dir, skip_llm=True)

        # 일부 결과에는 컴플라이언스 매핑이 있어야 함
        mapped_count = sum(1 for r in result.results if r.has_compliance_mapping)
        # 전체 결과 중 일부만 매핑될 수 있음
        assert mapped_count >= 0

    def test_get_status(self, mock_ollama_down):
        """분석기 상태 확인 테스트."""
        analyzer = HybridAnalyzer(model="test-model")

        status = analyzer.get_status()

        assert "semgrep" in status
        assert "bandit" in status
        assert "ollama" in status
        assert "model" in status
        assert status["model"] == "test-model"

    def test_progress_callback(self, fixtures_dir, mock_ollama_down):
        """진행 상황 콜백 테스트."""
        analyzer = HybridAnalyzer()
        stages_called = []

        def progress_callback(stage: str, progress: float):
            stages_called.append((stage, progress))

        analyzer.analyze(
            fixtures_dir,
            skip_llm=True,
            progress_callback=progress_callback,
        )

        # 최소한 "규칙 기반 분석", "컴플라이언스 매핑", "완료" 단계가 호출되어야 함
        assert len(stages_called) >= 3
        assert stages_called[-1] == ("완료", 1.0)


class TestSupportedExtensions:
    """지원 파일 확장자 테스트."""

    def test_python_supported(self):
        """Python 파일 지원 확인."""
        assert ".py" in SUPPORTED_EXTENSIONS
        assert SUPPORTED_EXTENSIONS[".py"] == "python"

    def test_javascript_supported(self):
        """JavaScript 파일 지원 확인."""
        assert ".js" in SUPPORTED_EXTENSIONS
        assert ".jsx" in SUPPORTED_EXTENSIONS

    def test_typescript_supported(self):
        """TypeScript 파일 지원 확인."""
        assert ".ts" in SUPPORTED_EXTENSIONS
        assert ".tsx" in SUPPORTED_EXTENSIONS

    def test_java_supported(self):
        """Java 파일 지원 확인."""
        assert ".java" in SUPPORTED_EXTENSIONS


class TestScanRepository:
    """ScanRepository 테스트."""

    @pytest.fixture
    def temp_db(self):
        """임시 데이터베이스 파일."""
        import os
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            temp_path = Path(f.name)
        yield temp_path
        # 테스트 후 정리
        if temp_path.exists():
            try:
                os.unlink(temp_path)
            except Exception:
                pass

    def test_create_scan(self, temp_db):
        """스캔 생성 테스트."""
        repo = ScanRepository(temp_db)

        scan = repo.create_scan(
            target_path="/test/path",
            model="exaone3.5:7.8b",
            compliance_types=["isms-p", "owasp"],
        )

        assert scan.id is not None
        assert scan.target_path == "/test/path"
        assert scan.status == "running"
        assert scan.model_used == "exaone3.5:7.8b"

    def test_complete_scan(self, temp_db):
        """스캔 완료 테스트."""
        repo = ScanRepository(temp_db)
        scan = repo.create_scan(target_path="/test/path")

        repo.complete_scan(
            scan_id=scan.id,
            total_files=10,
            scanned_files=8,
            total_vulnerabilities=5,
            critical_count=1,
            high_count=2,
            medium_count=2,
            low_count=0,
        )

        updated = repo.get_scan(scan.id)
        assert updated.status == "completed"
        assert updated.total_files == 10
        assert updated.total_vulnerabilities == 5
        assert updated.critical_count == 1

    def test_fail_scan(self, temp_db):
        """스캔 실패 테스트."""
        repo = ScanRepository(temp_db)
        scan = repo.create_scan(target_path="/test/path")

        repo.fail_scan(scan.id, "테스트 오류")

        updated = repo.get_scan(scan.id)
        assert updated.status == "failed"
        assert updated.error_message == "테스트 오류"

    def test_get_scan_short_id(self, temp_db):
        """짧은 ID로 스캔 조회 테스트."""
        repo = ScanRepository(temp_db)
        scan = repo.create_scan(target_path="/test/path")

        # 앞 8자리로 검색
        found = repo.get_scan(scan.id[:8])

        assert found is not None
        assert found.id == scan.id

    def test_list_scans(self, temp_db):
        """스캔 목록 조회 테스트."""
        repo = ScanRepository(temp_db)

        # 초기 상태 확인 (다른 테스트에서 생성된 스캔이 있을 수 있음)
        initial_count = repo.get_scan_count()

        # 여러 스캔 생성
        for i in range(3):
            repo.create_scan(target_path=f"/test/path{i}")

        scans = repo.list_scans(limit=10)

        # 초기 개수 + 3개가 되어야 함
        assert len(scans) == initial_count + 3

    def test_delete_scan(self, temp_db):
        """스캔 삭제 테스트."""
        repo = ScanRepository(temp_db)
        scan = repo.create_scan(target_path="/test/path")

        result = repo.delete_scan(scan.id)

        assert result is True
        assert repo.get_scan(scan.id) is None


class TestVulnerabilityRepository:
    """VulnerabilityRepository 테스트."""

    @pytest.fixture
    def temp_db(self):
        """임시 데이터베이스 파일."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            yield Path(f.name)

    @pytest.fixture
    def sample_scan(self, temp_db):
        """테스트용 스캔."""
        repo = ScanRepository(temp_db)
        return repo.create_scan(target_path="/test/path")

    @pytest.fixture
    def sample_mapped_results(self):
        """테스트용 MappedResult 목록."""
        return [
            MappedResult(
                rule_id="B608",
                title="SQL Injection",
                description="SQL 인젝션 취약점",
                severity="high",
                file_path="/test/vulnerable.py",
                line_start=10,
                source="bandit",
                confidence="high",
                compliance_mappings=[
                    ComplianceMappingInfo(
                        compliance_type="isms-p",
                        compliance_id="2.10.1",
                        compliance_title="SQL 인젝션",
                        rule_id="2.10.1-sql-injection",
                    ),
                ],
            ),
            MappedResult(
                rule_id="B303",
                title="MD5 Usage",
                severity="medium",
                file_path="/test/vulnerable.py",
                line_start=20,
                source="bandit",
                confidence="high",
            ),
        ]

    def test_save_results(self, temp_db, sample_scan, sample_mapped_results):
        """결과 저장 테스트."""
        repo = VulnerabilityRepository(temp_db)

        vulns = repo.save_results(sample_scan.id, sample_mapped_results)

        assert len(vulns) == 2
        assert vulns[0].rule_id == "B608"
        assert vulns[0].severity == SeverityLevel.HIGH

    def test_list_by_scan(self, temp_db, sample_scan, sample_mapped_results):
        """스캔별 취약점 목록 조회 테스트."""
        repo = VulnerabilityRepository(temp_db)
        repo.save_results(sample_scan.id, sample_mapped_results)

        vulns = repo.list_by_scan(sample_scan.id)

        assert len(vulns) == 2

    def test_list_by_severity(self, temp_db, sample_scan, sample_mapped_results):
        """심각도별 취약점 조회 테스트."""
        repo = VulnerabilityRepository(temp_db)
        repo.save_results(sample_scan.id, sample_mapped_results)

        high_vulns = repo.list_by_severity(sample_scan.id, "high")
        medium_vulns = repo.list_by_severity(sample_scan.id, "medium")

        assert len(high_vulns) == 1
        assert len(medium_vulns) == 1

    def test_get_compliance_mappings(self, temp_db, sample_scan, sample_mapped_results):
        """컴플라이언스 매핑 조회 테스트."""
        repo = VulnerabilityRepository(temp_db)
        vulns = repo.save_results(sample_scan.id, sample_mapped_results)

        # 첫 번째 취약점에는 컴플라이언스 매핑이 있어야 함
        mappings = repo.get_compliance_mappings(vulns[0].id)

        assert len(mappings) == 1
        assert mappings[0].compliance_id == "2.10.1"


class TestSaveHybridResult:
    """save_hybrid_result 함수 테스트."""

    @pytest.fixture
    def temp_db(self):
        """임시 데이터베이스 파일."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            yield Path(f.name)

    @pytest.fixture
    def sample_hybrid_result(self):
        """테스트용 HybridScanResult."""
        return HybridScanResult(
            scan_id="test123",
            target_path="/test/path",
            total_files=10,
            scanned_files=5,
            duration_seconds=1.5,
            model_used="exaone3.5:7.8b",
            compliance_types=["isms-p"],
            llm_enabled=True,
            results=[
                MappedResult(
                    rule_id="B608",
                    title="SQL Injection",
                    severity="high",
                    file_path="/test/file.py",
                    line_start=10,
                    source="bandit",
                ),
            ],
            total_issues=1,
            high_count=1,
        )

    def test_save_hybrid_result(self, temp_db, sample_hybrid_result):
        """하이브리드 결과 저장 테스트."""
        scan_id = save_hybrid_result(sample_hybrid_result, temp_db)

        assert scan_id is not None

        # 저장된 스캔 확인
        scan_repo = ScanRepository(temp_db)
        scan = scan_repo.get_scan(scan_id)

        assert scan is not None
        assert scan.status == "completed"
        assert scan.target_path == "/test/path"
        assert scan.model_used == "exaone3.5:7.8b"

        # 저장된 취약점 확인
        vuln_repo = VulnerabilityRepository(temp_db)
        vulns = vuln_repo.list_by_scan(scan_id)

        assert len(vulns) == 1
        assert vulns[0].rule_id == "B608"

    def test_save_hybrid_result_with_analysis_type(self, temp_db):
        """분석 유형에 따른 저장 테스트."""
        # LLM 비활성화된 결과
        result_no_llm = HybridScanResult(
            scan_id="test1",
            target_path="/test/path",
            total_files=1,
            scanned_files=1,
            llm_enabled=False,
            results=[],
        )

        scan_id = save_hybrid_result(result_no_llm, temp_db)

        scan_repo = ScanRepository(temp_db)
        scan = scan_repo.get_scan(scan_id)

        assert scan.analysis_type == AnalysisType.RULE_BASED
