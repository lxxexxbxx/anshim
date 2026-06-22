# anshim/core/compliance/loader.py
"""컴플라이언스 룰셋 로더.

YAML 파일에서 컴플라이언스 룰을 로드하고 파싱합니다.
"""

import logging
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


class ComplianceRule(BaseModel):
    """컴플라이언스 룰 모델.

    YAML 룰셋 파일의 구조를 표현합니다.
    """

    id: str = Field(..., description="룰 ID (예: 2.10.1-sql-injection)")
    title: str = Field(..., description="룰 제목")
    description: str = Field(default="", description="상세 설명")
    category: str = Field(default="", description="카테고리 (예: 2.10 시스템 및 서비스 보안 관리)")
    subcategory: str = Field(default="", description="서브카테고리")

    applicable_to: list[str] = Field(
        default_factory=list,
        description="적용 대상 (isms, isms-p, owasp, cwe)",
    )
    severity: str = Field(default="medium", description="심각도")
    languages: list[str] = Field(
        default_factory=list,
        description="적용 언어 (python, java, javascript 등)",
    )

    # 규칙 기반 분석기 매핑
    semgrep_rule_ids: list[str] = Field(
        default_factory=list,
        description="매핑된 Semgrep 룰 ID 목록",
    )
    bandit_test_ids: list[str] = Field(
        default_factory=list,
        description="매핑된 Bandit 테스트 ID 목록",
    )

    # 취약 패턴 및 수정 제안
    vulnerable_patterns: dict[str, list[str]] = Field(
        default_factory=dict,
        description="언어별 취약 패턴 예시",
    )
    remediation: dict[str, str] = Field(
        default_factory=dict,
        description="수정 권장사항 (ko/en)",
    )

    # 외부 표준 매핑
    cwe_ids: list[str] = Field(
        default_factory=list,
        description="관련 CWE ID 목록",
    )
    owasp_ids: list[str] = Field(
        default_factory=list,
        description="관련 OWASP ID 목록",
    )
    references: list[str] = Field(
        default_factory=list,
        description="참조 URL 목록",
    )

    # 추가 메타데이터
    personal_info_keywords: list[str] = Field(
        default_factory=list,
        description="개인정보 탐지 키워드 (ISMS-P용)",
    )
    korean_regulations: list[str] = Field(
        default_factory=list,
        description="관련 한국 법규",
    )

    source_file: Optional[str] = Field(
        default=None,
        description="원본 YAML 파일 경로",
    )

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """심각도 값 검증."""
        valid_severities = {"critical", "high", "medium", "low", "info"}
        v_lower = v.lower()
        if v_lower not in valid_severities:
            logger.warning("알 수 없는 심각도 '%s', 'medium'으로 기본 설정", v)
            return "medium"
        return v_lower

    @field_validator("applicable_to")
    @classmethod
    def validate_applicable_to(cls, v: list[str]) -> list[str]:
        """적용 대상 값 검증."""
        valid_types = {"isms", "isms-p", "owasp", "cwe"}
        return [t.lower() for t in v if t.lower() in valid_types]

    def matches_rule_id(self, rule_id: str) -> bool:
        """분석 결과의 rule_id가 이 룰과 매핑되는지 확인.

        Args:
            rule_id: 분석 결과의 rule_id (Semgrep 또는 Bandit).

        Returns:
            매핑되면 True.
        """
        # Semgrep 룰 ID 매칭
        for semgrep_id in self.semgrep_rule_ids:
            # 부분 매칭 지원 (접두사 매칭)
            if rule_id.startswith(semgrep_id) or semgrep_id in rule_id:
                return True

        # Bandit 테스트 ID 매칭 (B### 형식)
        for bandit_id in self.bandit_test_ids:
            if rule_id.upper() == bandit_id.upper():
                return True
            # rule_id가 "B608: hardcoded_sql_expressions" 형태인 경우
            if rule_id.upper().startswith(bandit_id.upper()):
                return True

        return False

    def is_applicable(self, compliance_types: list[str]) -> bool:
        """지정된 컴플라이언스 유형에 적용 가능한지 확인.

        Args:
            compliance_types: 확인할 컴플라이언스 유형 목록.

        Returns:
            하나라도 매칭되면 True.
        """
        compliance_types_lower = [t.lower() for t in compliance_types]

        # "all" 지정 시 모든 룰 적용
        if "all" in compliance_types_lower:
            return True

        # applicable_to와 교집합 확인
        return bool(set(self.applicable_to) & set(compliance_types_lower))


class RuleLoader:
    """컴플라이언스 룰 로더.

    rules/ 디렉토리에서 YAML 파일을 읽어 ComplianceRule 목록을 생성합니다.
    """

    def __init__(self, rules_dir: Optional[Path] = None):
        """RuleLoader 초기화.

        Args:
            rules_dir: 룰셋 디렉토리 경로. None이면 기본 경로 사용.
        """
        if rules_dir is None:
            # 기본 경로: anshim/rules
            rules_dir = Path(__file__).parent.parent.parent / "rules"
        self.rules_dir = rules_dir.resolve()
        self._rules: list[ComplianceRule] = []
        self._loaded = False

    def load_rules(self) -> list[ComplianceRule]:
        """모든 YAML 룰셋 파일 로드.

        Returns:
            로드된 ComplianceRule 목록.
        """
        if self._loaded:
            return self._rules

        if not self.rules_dir.exists():
            logger.warning("룰셋 디렉토리가 존재하지 않습니다: %s", self.rules_dir)
            return []

        self._rules = []

        # 재귀적으로 YAML 파일 탐색
        yaml_files = list(self.rules_dir.rglob("*.yaml")) + list(
            self.rules_dir.rglob("*.yml")
        )

        logger.info("룰셋 파일 %d개 발견: %s", len(yaml_files), self.rules_dir)

        for yaml_path in yaml_files:
            try:
                rule = self._load_rule_file(yaml_path)
                if rule:
                    self._rules.append(rule)
            except Exception as e:
                logger.error("룰 파일 로드 실패 (%s): %s", yaml_path, e)

        self._loaded = True
        logger.info("총 %d개 룰 로드 완료", len(self._rules))

        return self._rules

    def _load_rule_file(self, yaml_path: Path) -> Optional[ComplianceRule]:
        """개별 YAML 파일 로드.

        Args:
            yaml_path: YAML 파일 경로.

        Returns:
            파싱된 ComplianceRule 또는 None.
        """
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            logger.warning("빈 YAML 파일: %s", yaml_path)
            return None

        if "id" not in data:
            logger.warning("id 필드 없음, 스킵: %s", yaml_path)
            return None

        # source_file 추가
        data["source_file"] = str(yaml_path.relative_to(self.rules_dir))

        return ComplianceRule(**data)

    def get_rules_by_compliance(
        self,
        compliance_types: list[str],
    ) -> list[ComplianceRule]:
        """컴플라이언스 유형으로 룰 필터링.

        Args:
            compliance_types: 필터링할 컴플라이언스 유형 목록.

        Returns:
            해당 유형에 적용 가능한 룰 목록.
        """
        if not self._loaded:
            self.load_rules()

        return [
            rule for rule in self._rules if rule.is_applicable(compliance_types)
        ]

    def get_rule_by_id(self, rule_id: str) -> Optional[ComplianceRule]:
        """룰 ID로 룰 조회.

        Args:
            rule_id: 조회할 룰 ID.

        Returns:
            해당 룰 또는 None.
        """
        if not self._loaded:
            self.load_rules()

        for rule in self._rules:
            if rule.id == rule_id:
                return rule
        return None

    def find_matching_rules(
        self,
        analysis_rule_id: str,
        compliance_types: Optional[list[str]] = None,
    ) -> list[ComplianceRule]:
        """분석 결과의 rule_id에 매핑되는 룰 찾기.

        Args:
            analysis_rule_id: 분석 결과의 rule_id (Semgrep/Bandit).
            compliance_types: 필터링할 컴플라이언스 유형. None이면 전체.

        Returns:
            매핑되는 룰 목록.
        """
        if not self._loaded:
            self.load_rules()

        rules = self._rules
        if compliance_types:
            rules = [r for r in rules if r.is_applicable(compliance_types)]

        return [rule for rule in rules if rule.matches_rule_id(analysis_rule_id)]

    @property
    def all_rules(self) -> list[ComplianceRule]:
        """모든 룰 반환."""
        if not self._loaded:
            self.load_rules()
        return self._rules

    def reload(self) -> list[ComplianceRule]:
        """룰셋 다시 로드.

        Returns:
            다시 로드된 룰 목록.
        """
        self._loaded = False
        self._rules = []
        return self.load_rules()
