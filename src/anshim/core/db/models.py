"""
SQLite 데이터베이스 모델 정의.

SQLAlchemy ORM을 사용하여 테이블 스키마를 정의합니다.
"""

import enum
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """SQLAlchemy 선언적 베이스 클래스."""

    pass


class SeverityLevel(enum.Enum):
    """취약점 심각도 수준."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceType(enum.Enum):
    """컴플라이언스 유형."""

    ISMS = "isms"
    ISMS_P = "isms-p"
    OWASP = "owasp"
    CWE = "cwe"


class AnalysisType(enum.Enum):
    """분석 유형."""

    RULE_BASED = "rule_based"
    LLM_BASED = "llm_based"
    HYBRID = "hybrid"


class Scan(Base):
    """
    스캔 세션 테이블.

    각 스캔 실행에 대한 메타데이터를 저장합니다.
    """

    __tablename__ = "scans"

    id = Column(String(36), primary_key=True)  # UUID
    target_path = Column(String(500), nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="running", nullable=False)  # running, completed, failed
    analysis_type = Column(Enum(AnalysisType), default=AnalysisType.HYBRID, nullable=False)
    model_used = Column(String(100), nullable=True)
    compliance_types = Column(JSON, nullable=True)  # ["isms-p", "owasp"]
    total_files = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

    # 관계
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, target={self.target_path}, status={self.status})>"


class Vulnerability(Base):
    """
    발견된 취약점 테이블.

    각 취약점의 상세 정보를 저장합니다.
    """

    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(String(100), nullable=True)  # 규칙 기반 분석 시
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(SeverityLevel), nullable=False)
    file_path = Column(String(500), nullable=False)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    analysis_type = Column(Enum(AnalysisType), nullable=False)
    is_false_positive = Column(Boolean, default=False)
    confidence = Column(Integer, default=100)  # 0-100, LLM 분석 시 신뢰도
    attack_scenario = Column(Text, nullable=True)  # LLM 생성 공격 시나리오
    remediation = Column(Text, nullable=True)  # 수정 제안
    remediation_code = Column(Text, nullable=True)  # 수정 코드 예시
    git_commit = Column(String(40), nullable=True)  # 취약점 도입 커밋
    git_author = Column(String(100), nullable=True)  # 커밋 작성자
    git_date = Column(DateTime, nullable=True)  # 커밋 날짜
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    extra_data = Column(JSON, nullable=True)  # 추가 메타데이터

    # 관계
    scan = relationship("Scan", back_populates="vulnerabilities")
    compliance_mappings = relationship(
        "ComplianceMapping", back_populates="vulnerability", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Vulnerability(id={self.id}, title={self.title}, severity={self.severity})>"


class ComplianceMapping(Base):
    """
    컴플라이언스 매핑 테이블.

    취약점과 컴플라이언스 항목 간의 매핑을 저장합니다.
    """

    __tablename__ = "compliance_mappings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    compliance_type = Column(Enum(ComplianceType), nullable=False)
    compliance_id = Column(String(50), nullable=False)  # 예: "2.7.1", "A01:2021"
    compliance_title = Column(String(200), nullable=True)
    compliance_category = Column(String(100), nullable=True)
    notes = Column(Text, nullable=True)

    # 관계
    vulnerability = relationship("Vulnerability", back_populates="compliance_mappings")

    def __repr__(self) -> str:
        return f"<ComplianceMapping(id={self.id}, type={self.compliance_type}, compliance_id={self.compliance_id})>"


class Rule(Base):
    """
    보안 규칙 캐시 테이블.

    YAML 룰셋에서 로드한 규칙을 캐싱합니다.
    """

    __tablename__ = "rules"

    id = Column(String(100), primary_key=True)
    title = Column(String(200), nullable=False)
    category = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    severity = Column(Enum(SeverityLevel), nullable=False)
    applicable_to = Column(JSON, nullable=True)  # ["isms", "isms-p", "owasp"]
    languages = Column(JSON, nullable=True)  # ["python", "java", "javascript"]
    patterns = Column(JSON, nullable=True)  # 패턴 목록
    references = Column(JSON, nullable=True)  # 참조 URL 목록
    is_active = Column(Boolean, default=True)
    source_file = Column(String(200), nullable=True)  # YAML 파일 경로
    loaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    extra_data = Column(JSON, nullable=True)

    def __repr__(self) -> str:
        return f"<Rule(id={self.id}, title={self.title})>"


class Config(Base):
    """
    사용자 설정 테이블.

    AnShim 전역 설정을 저장합니다.
    """

    __tablename__ = "configs"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=True)
    value_type = Column(String(20), default="string")  # string, int, bool, json
    description = Column(String(200), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Config(key={self.key}, value={self.value})>"
