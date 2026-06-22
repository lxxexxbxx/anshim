# anshim/tests/test_compliance_mapper.py
"""컴플라이언스 매퍼 테스트."""

import pytest
from pathlib import Path

from anshim.core.analyzers.models import AnalysisResult
from anshim.core.compliance.loader import ComplianceRule, RuleLoader
from anshim.core.compliance.mapper import ComplianceMapper, MappedResult


class TestComplianceRule:
    """ComplianceRule 모델 테스트."""

    def test_rule_creation(self):
        """기본 룰 생성 테스트."""
        rule = ComplianceRule(
            id="test-rule",
            title="테스트 룰",
            applicable_to=["isms", "isms-p"],
            severity="high",
        )
        assert rule.id == "test-rule"
        assert rule.severity == "high"
        assert "isms" in rule.applicable_to

    def test_severity_validation(self):
        """심각도 유효성 검증 테스트."""
        rule = ComplianceRule(
            id="test-rule",
            title="테스트 룰",
            severity="INVALID",
        )
        # 잘못된 심각도는 medium으로 기본 설정
        assert rule.severity == "medium"

    def test_applicable_to_validation(self):
        """적용 대상 유효성 검증 테스트."""
        rule = ComplianceRule(
            id="test-rule",
            title="테스트 룰",
            applicable_to=["isms", "invalid", "owasp"],
        )
        # 유효하지 않은 값은 제거됨
        assert "invalid" not in rule.applicable_to
        assert "isms" in rule.applicable_to
        assert "owasp" in rule.applicable_to

    def test_matches_rule_id_semgrep(self):
        """Semgrep 룰 ID 매칭 테스트."""
        rule = ComplianceRule(
            id="2.10.1-sql-injection",
            title="SQL 인젝션",
            semgrep_rule_ids=[
                "python.django.security.injection.sql",
                "python.flask.security.injection.sql-injection",
            ],
        )
        assert rule.matches_rule_id("python.django.security.injection.sql.raw-query")
        assert rule.matches_rule_id("python.flask.security.injection.sql-injection")
        assert not rule.matches_rule_id("python.cryptography.security.insecure-hash")

    def test_matches_rule_id_bandit(self):
        """Bandit 테스트 ID 매칭 테스트."""
        rule = ComplianceRule(
            id="2.10.1-sql-injection",
            title="SQL 인젝션",
            bandit_test_ids=["B608", "B610"],
        )
        assert rule.matches_rule_id("B608")
        assert rule.matches_rule_id("B608: hardcoded_sql_expressions")
        assert not rule.matches_rule_id("B303")

    def test_is_applicable_isms(self):
        """ISMS 적용 가능 여부 테스트."""
        rule = ComplianceRule(
            id="test-rule",
            title="테스트 룰",
            applicable_to=["isms", "isms-p"],
        )
        assert rule.is_applicable(["isms"])
        assert rule.is_applicable(["isms-p"])
        assert rule.is_applicable(["isms", "owasp"])
        assert not rule.is_applicable(["owasp"])

    def test_is_applicable_all(self):
        """all 컴플라이언스 유형 테스트."""
        rule = ComplianceRule(
            id="test-rule",
            title="테스트 룰",
            applicable_to=["isms-p"],
        )
        # "all" 지정 시 모든 룰 적용
        assert rule.is_applicable(["all"])

    def test_is_applicable_isms_p_only(self):
        """ISMS-P 전용 룰 테스트."""
        rule = ComplianceRule(
            id="3.2.1-personal-info",
            title="개인정보 암호화",
            applicable_to=["isms-p"],  # ISMS-P 전용
        )
        assert not rule.is_applicable(["isms"])  # ISMS만 선택 시 제외
        assert rule.is_applicable(["isms-p"])


class TestRuleLoader:
    """RuleLoader 테스트."""

    @pytest.fixture
    def rules_dir(self):
        """테스트용 rules 디렉토리."""
        return Path(__file__).parent.parent / "rules"

    def test_load_rules(self, rules_dir):
        """룰셋 로드 테스트."""
        loader = RuleLoader(rules_dir)
        rules = loader.load_rules()

        assert len(rules) > 0
        # 기본 룰들이 로드되었는지 확인
        rule_ids = [r.id for r in rules]
        assert "2.10.1-sql-injection" in rule_ids

    def test_get_rules_by_compliance_isms(self, rules_dir):
        """ISMS 룰 필터링 테스트."""
        loader = RuleLoader(rules_dir)
        loader.load_rules()

        isms_rules = loader.get_rules_by_compliance(["isms"])
        isms_p_rules = loader.get_rules_by_compliance(["isms-p"])

        # ISMS-P 전용 룰(3.x_personal_info)은 ISMS에 포함되지 않음
        isms_rule_ids = [r.id for r in isms_rules]
        isms_p_rule_ids = [r.id for r in isms_p_rules]

        # 3.2.1-personal-info-encryption은 ISMS-P 전용
        assert "3.2.1-personal-info-encryption" not in isms_rule_ids
        assert "3.2.1-personal-info-encryption" in isms_p_rule_ids

    def test_get_rules_by_compliance_owasp(self, rules_dir):
        """OWASP 룰 필터링 테스트."""
        loader = RuleLoader(rules_dir)
        loader.load_rules()

        owasp_rules = loader.get_rules_by_compliance(["owasp"])
        assert len(owasp_rules) > 0

        # OWASP 룰이 포함되어 있는지 확인
        owasp_rule_ids = [r.id for r in owasp_rules]
        # A03-injection 또는 관련 룰이 있어야 함
        assert any("A0" in rid or "injection" in rid.lower() for rid in owasp_rule_ids)

    def test_find_matching_rules(self, rules_dir):
        """분석 결과 rule_id와 매칭되는 룰 찾기 테스트."""
        loader = RuleLoader(rules_dir)
        loader.load_rules()

        # SQL Injection 관련 Bandit 룰 ID로 검색
        matches = loader.find_matching_rules("B608")
        assert len(matches) > 0
        assert any("sql" in r.id.lower() for r in matches)


class TestComplianceMapper:
    """ComplianceMapper 테스트."""

    @pytest.fixture
    def rules_dir(self):
        """테스트용 rules 디렉토리."""
        return Path(__file__).parent.parent / "rules"

    @pytest.fixture
    def sample_result(self):
        """테스트용 분석 결과."""
        return AnalysisResult(
            rule_id="B608",
            title="SQL Injection via string formatting",
            description="Possible SQL injection via string formatting",
            severity="high",
            file_path="/test/vulnerable.py",
            line_start=10,
            source="bandit",
            confidence="high",
        )

    def test_map_result_with_matching_rule(self, rules_dir, sample_result):
        """룰과 매칭되는 결과 매핑 테스트."""
        mapper = ComplianceMapper(
            rules_dir=rules_dir,
            compliance_types=["isms-p", "owasp"],
        )

        mapped = mapper.map_result(sample_result)

        assert isinstance(mapped, MappedResult)
        assert mapped.rule_id == sample_result.rule_id
        assert mapped.has_compliance_mapping

        # 컴플라이언스 매핑 확인
        comp_types = mapped.compliance_types
        # SQL 인젝션은 ISMS-P와 OWASP 모두 해당
        assert "isms-p" in comp_types or "owasp" in comp_types

    def test_map_result_without_matching_rule(self, rules_dir):
        """매칭되는 룰이 없는 결과 매핑 테스트."""
        mapper = ComplianceMapper(
            rules_dir=rules_dir,
            compliance_types=["isms-p"],
        )

        result = AnalysisResult(
            rule_id="unknown.rule.id",
            title="Unknown Vulnerability",
            severity="low",
            file_path="/test/file.py",
            line_start=1,
            source="test",
        )

        mapped = mapper.map_result(result)

        assert isinstance(mapped, MappedResult)
        # 매칭되는 룰이 없어도 기본 정보는 유지
        assert mapped.rule_id == "unknown.rule.id"
        assert not mapped.has_compliance_mapping

    def test_map_results_batch(self, rules_dir, sample_result):
        """여러 결과 배치 매핑 테스트."""
        mapper = ComplianceMapper(
            rules_dir=rules_dir,
            compliance_types=["isms-p"],
        )

        results = [sample_result, sample_result]
        mapped_results = mapper.map_results(results)

        assert len(mapped_results) == 2
        for mapped in mapped_results:
            assert isinstance(mapped, MappedResult)

    def test_compliance_filter_isms_only(self, rules_dir):
        """ISMS만 선택 시 ISMS-P 전용 룰 제외 테스트."""
        mapper = ComplianceMapper(
            rules_dir=rules_dir,
            compliance_types=["isms"],  # ISMS만 선택
        )
        mapper.load_rules()

        # ISMS-P 전용 룰이 로드되지 않았는지 확인
        rule_ids = [r.id for r in mapper.loader.get_rules_by_compliance(["isms"])]
        assert "3.2.1-personal-info-encryption" not in rule_ids

    def test_get_compliance_summary(self, rules_dir, sample_result):
        """컴플라이언스 요약 통계 테스트."""
        mapper = ComplianceMapper(
            rules_dir=rules_dir,
            compliance_types=["isms-p", "owasp", "cwe"],
        )

        mapped_results = mapper.map_results([sample_result])
        summary = mapper.get_compliance_summary(mapped_results)

        assert "isms-p" in summary
        assert "owasp" in summary
        assert "cwe" in summary
        assert "total" in summary["isms-p"]


class TestMappedResult:
    """MappedResult 모델 테스트."""

    def test_from_analysis_result(self):
        """AnalysisResult에서 MappedResult 생성 테스트."""
        result = AnalysisResult(
            rule_id="test-rule",
            title="Test Vulnerability",
            severity="high",
            file_path="/test/file.py",
            line_start=10,
            source="test",
        )

        mapped = MappedResult.from_analysis_result(result, mappings=[])

        assert mapped.rule_id == "test-rule"
        assert mapped.severity == "high"
        assert mapped.file_path == "/test/file.py"
        assert not mapped.has_compliance_mapping

    def test_unique_key(self):
        """고유 키 생성 테스트."""
        mapped = MappedResult(
            rule_id="test-rule",
            title="Test",
            severity="high",
            file_path="/test/file.py",
            line_start=10,
            source="test",
        )

        key = mapped.unique_key()
        assert key == "/test/file.py:10:test-rule"
