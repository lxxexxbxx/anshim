# anshim/core/compliance/mapper.py
"""컴플라이언스 매퍼.

분석 결과에 컴플라이언스 정보를 매핑합니다.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from anshim.core.analyzers.models import AnalysisResult
from anshim.core.compliance.loader import ComplianceRule, RuleLoader

logger = logging.getLogger(__name__)


class ComplianceMappingInfo(BaseModel):
    """개별 컴플라이언스 매핑 정보."""

    compliance_type: str = Field(..., description="컴플라이언스 유형 (isms, isms-p, owasp, cwe)")
    compliance_id: str = Field(..., description="컴플라이언스 항목 ID")
    compliance_title: str = Field(default="", description="컴플라이언스 항목 제목")
    compliance_category: str = Field(default="", description="카테고리")
    rule_id: str = Field(..., description="매핑된 AnShim 룰 ID")
    remediation_ko: str = Field(default="", description="한국어 수정 권장사항")
    remediation_en: str = Field(default="", description="영문 수정 권장사항")
    references: list[str] = Field(default_factory=list, description="참조 URL")
    korean_regulations: list[str] = Field(
        default_factory=list,
        description="관련 한국 법규",
    )


class MappedResult(BaseModel):
    """컴플라이언스가 매핑된 분석 결과.

    기존 AnalysisResult에 컴플라이언스 매핑 정보가 추가된 형태.
    """

    # 원본 AnalysisResult 필드들
    rule_id: str
    title: str
    description: str = ""
    severity: str
    file_path: str
    line_start: int
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    source: str
    confidence: str = "medium"

    # LLM 분석 결과 (있는 경우)
    llm_analysis: Optional[str] = None
    is_false_positive: bool = False
    severity_adjusted: Optional[str] = None
    isms_relevance: Optional[str] = None
    attack_scenario: Optional[dict] = None
    remediation: Optional[dict] = None

    # 컴플라이언스 매핑
    compliance_mappings: list[ComplianceMappingInfo] = Field(
        default_factory=list,
        description="매핑된 컴플라이언스 정보 목록",
    )

    class Config:
        """Pydantic 설정."""

        extra = "allow"

    @classmethod
    def from_analysis_result(
        cls,
        result: AnalysisResult,
        mappings: list[ComplianceMappingInfo],
    ) -> "MappedResult":
        """AnalysisResult에서 MappedResult 생성.

        Args:
            result: 원본 분석 결과.
            mappings: 컴플라이언스 매핑 정보 목록.

        Returns:
            컴플라이언스가 매핑된 결과.
        """
        # 원본 데이터 추출
        data = result.model_dump()

        # MappedResult 생성에 필요한 필드만 추출
        mapped_data = {
            "rule_id": data.get("rule_id", ""),
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "severity": data.get("severity", "medium"),
            "file_path": data.get("file_path", ""),
            "line_start": data.get("line_start", 1),
            "line_end": data.get("line_end"),
            "code_snippet": data.get("code_snippet"),
            "source": data.get("source", ""),
            "confidence": data.get("confidence", "medium"),
            "compliance_mappings": mappings,
        }

        # LLM 분석 결과 추가 (있는 경우)
        for llm_field in [
            "llm_analysis",
            "is_false_positive",
            "severity_adjusted",
            "isms_relevance",
            "attack_scenario",
            "remediation",
        ]:
            if llm_field in data:
                mapped_data[llm_field] = data[llm_field]

        return cls(**mapped_data)

    @property
    def has_compliance_mapping(self) -> bool:
        """컴플라이언스 매핑이 있는지 확인."""
        return len(self.compliance_mappings) > 0

    @property
    def compliance_types(self) -> set[str]:
        """매핑된 컴플라이언스 유형들."""
        return {m.compliance_type for m in self.compliance_mappings}

    def unique_key(self) -> str:
        """중복 제거를 위한 고유 키."""
        return f"{self.file_path}:{self.line_start}:{self.rule_id}"


class ComplianceMapper:
    """컴플라이언스 매퍼.

    분석 결과에 ISMS/ISMS-P/OWASP/CWE 컴플라이언스 정보를 매핑합니다.
    """

    def __init__(
        self,
        rules_dir: Optional[Path] = None,
        compliance_types: Optional[list[str]] = None,
    ):
        """ComplianceMapper 초기화.

        Args:
            rules_dir: 룰셋 디렉토리 경로.
            compliance_types: 매핑할 컴플라이언스 유형 목록.
        """
        self.loader = RuleLoader(rules_dir)
        self.compliance_types = compliance_types or ["isms-p"]
        self._rules: list[ComplianceRule] = []

    def load_rules(self) -> None:
        """룰셋 로드."""
        self._rules = self.loader.get_rules_by_compliance(self.compliance_types)
        logger.info(
            "%d개 룰 로드 (컴플라이언스: %s)",
            len(self._rules),
            ", ".join(self.compliance_types),
        )

    def map_result(self, result: AnalysisResult) -> MappedResult:
        """개별 분석 결과에 컴플라이언스 매핑.

        Args:
            result: 분석 결과.

        Returns:
            컴플라이언스가 매핑된 결과.
        """
        if not self._rules:
            self.load_rules()

        # 매칭되는 룰 찾기
        matching_rules = self.loader.find_matching_rules(
            result.rule_id,
            self.compliance_types,
        )

        # 컴플라이언스 매핑 정보 생성
        mappings: list[ComplianceMappingInfo] = []

        for rule in matching_rules:
            # 각 applicable_to 유형에 대해 매핑 생성
            for comp_type in rule.applicable_to:
                if comp_type not in [t.lower() for t in self.compliance_types]:
                    if "all" not in [t.lower() for t in self.compliance_types]:
                        continue

                mapping = self._create_mapping_from_rule(rule, comp_type)
                mappings.append(mapping)

            # OWASP/CWE 매핑도 생성
            if "owasp" in [t.lower() for t in self.compliance_types] or "all" in [
                t.lower() for t in self.compliance_types
            ]:
                for owasp_id in rule.owasp_ids:
                    mappings.append(
                        ComplianceMappingInfo(
                            compliance_type="owasp",
                            compliance_id=owasp_id,
                            compliance_title=self._get_owasp_title(owasp_id),
                            compliance_category="OWASP Top 10",
                            rule_id=rule.id,
                            remediation_ko=rule.remediation.get("ko", ""),
                            remediation_en=rule.remediation.get("en", ""),
                            references=rule.references,
                        )
                    )

            if "cwe" in [t.lower() for t in self.compliance_types] or "all" in [
                t.lower() for t in self.compliance_types
            ]:
                for cwe_id in rule.cwe_ids:
                    mappings.append(
                        ComplianceMappingInfo(
                            compliance_type="cwe",
                            compliance_id=cwe_id,
                            compliance_title=self._get_cwe_title(cwe_id),
                            compliance_category="CWE Top 25",
                            rule_id=rule.id,
                            remediation_ko=rule.remediation.get("ko", ""),
                            remediation_en=rule.remediation.get("en", ""),
                            references=rule.references,
                        )
                    )

        # 중복 제거
        seen = set()
        unique_mappings = []
        for m in mappings:
            key = (m.compliance_type, m.compliance_id)
            if key not in seen:
                seen.add(key)
                unique_mappings.append(m)

        return MappedResult.from_analysis_result(result, unique_mappings)

    def map_results(self, results: list[AnalysisResult]) -> list[MappedResult]:
        """여러 분석 결과에 컴플라이언스 매핑.

        Args:
            results: 분석 결과 목록.

        Returns:
            컴플라이언스가 매핑된 결과 목록.
        """
        if not self._rules:
            self.load_rules()

        mapped_results = []
        for result in results:
            mapped = self.map_result(result)
            mapped_results.append(mapped)

        # 매핑 통계 로깅
        with_mapping = sum(1 for r in mapped_results if r.has_compliance_mapping)
        logger.info(
            "컴플라이언스 매핑 완료: %d/%d 결과에 매핑됨",
            with_mapping,
            len(mapped_results),
        )

        return mapped_results

    def _create_mapping_from_rule(
        self,
        rule: ComplianceRule,
        comp_type: str,
    ) -> ComplianceMappingInfo:
        """룰에서 컴플라이언스 매핑 정보 생성.

        Args:
            rule: 컴플라이언스 룰.
            comp_type: 컴플라이언스 유형.

        Returns:
            컴플라이언스 매핑 정보.
        """
        return ComplianceMappingInfo(
            compliance_type=comp_type,
            compliance_id=rule.id.split("-")[0] if "-" in rule.id else rule.id,
            compliance_title=rule.title,
            compliance_category=rule.category,
            rule_id=rule.id,
            remediation_ko=rule.remediation.get("ko", ""),
            remediation_en=rule.remediation.get("en", ""),
            references=rule.references,
            korean_regulations=rule.korean_regulations,
        )

    @staticmethod
    def _get_owasp_title(owasp_id: str) -> str:
        """OWASP ID에 해당하는 제목 반환."""
        owasp_titles = {
            "A01:2021": "Broken Access Control",
            "A02:2021": "Cryptographic Failures",
            "A03:2021": "Injection",
            "A04:2021": "Insecure Design",
            "A05:2021": "Security Misconfiguration",
            "A06:2021": "Vulnerable and Outdated Components",
            "A07:2021": "Identification and Authentication Failures",
            "A08:2021": "Software and Data Integrity Failures",
            "A09:2021": "Security Logging and Monitoring Failures",
            "A10:2021": "Server-Side Request Forgery",
        }
        return owasp_titles.get(owasp_id, owasp_id)

    @staticmethod
    def _get_cwe_title(cwe_id: str) -> str:
        """CWE ID에 해당하는 제목 반환."""
        cwe_titles = {
            "CWE-89": "SQL Injection",
            "CWE-79": "Cross-site Scripting (XSS)",
            "CWE-78": "OS Command Injection",
            "CWE-22": "Path Traversal",
            "CWE-798": "Use of Hard-coded Credentials",
            "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
            "CWE-328": "Reversible One-Way Hash",
            "CWE-311": "Missing Encryption of Sensitive Data",
            "CWE-312": "Cleartext Storage of Sensitive Information",
            "CWE-256": "Unprotected Storage of Credentials",
            "CWE-20": "Improper Input Validation",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-611": "Improper Restriction of XML External Entity Reference",
            "CWE-918": "Server-Side Request Forgery (SSRF)",
            "CWE-287": "Improper Authentication",
            "CWE-862": "Missing Authorization",
            "CWE-863": "Incorrect Authorization",
        }
        return cwe_titles.get(cwe_id, cwe_id)

    def get_compliance_summary(
        self,
        mapped_results: list[MappedResult],
    ) -> dict[str, dict]:
        """컴플라이언스별 요약 정보 생성.

        Args:
            mapped_results: 매핑된 결과 목록.

        Returns:
            컴플라이언스 유형별 통계.
        """
        summary: dict[str, dict] = {
            "isms": {"total": 0, "by_severity": {}},
            "isms-p": {"total": 0, "by_severity": {}},
            "owasp": {"total": 0, "by_severity": {}},
            "cwe": {"total": 0, "by_severity": {}},
        }

        for result in mapped_results:
            for mapping in result.compliance_mappings:
                comp_type = mapping.compliance_type
                if comp_type in summary:
                    summary[comp_type]["total"] += 1
                    severity = result.severity
                    if severity not in summary[comp_type]["by_severity"]:
                        summary[comp_type]["by_severity"][severity] = 0
                    summary[comp_type]["by_severity"][severity] += 1

        return summary
