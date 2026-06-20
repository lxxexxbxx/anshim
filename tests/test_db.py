"""
데이터베이스 모델 테스트.

SQLAlchemy ORM 모델의 CRUD 동작을 테스트합니다.
"""

from datetime import datetime

import pytest
from sqlalchemy.orm import Session

from anshim.core.db.models import (
    AnalysisType,
    ComplianceMapping,
    ComplianceType,
    Config,
    Rule,
    Scan,
    SeverityLevel,
    Vulnerability,
)


class TestScanModel:
    """Scan 모델 테스트."""

    def test_create_scan(self, db_session: Session, sample_scan_data: dict) -> None:
        """스캔 생성 테스트."""
        scan = Scan(**sample_scan_data)
        db_session.add(scan)
        db_session.commit()

        retrieved = db_session.query(Scan).filter_by(id=sample_scan_data["id"]).first()
        assert retrieved is not None
        assert retrieved.id == sample_scan_data["id"]
        assert retrieved.target_path == sample_scan_data["target_path"]
        assert retrieved.status == "completed"

    def test_scan_defaults(self, db_session: Session) -> None:
        """스캔 기본값 테스트."""
        scan = Scan(id="test-defaults", target_path="/tmp/test")
        db_session.add(scan)
        db_session.commit()

        assert scan.status == "running"
        assert scan.analysis_type == AnalysisType.HYBRID
        assert scan.total_files == 0
        assert scan.started_at is not None


class TestVulnerabilityModel:
    """Vulnerability 모델 테스트."""

    def test_create_vulnerability(
        self, db_session: Session, sample_scan_data: dict, sample_vulnerability_data: dict
    ) -> None:
        """취약점 생성 테스트."""
        scan = Scan(**sample_scan_data)
        db_session.add(scan)
        db_session.commit()

        vuln = Vulnerability(
            scan_id=scan.id,
            severity=SeverityLevel.HIGH,
            analysis_type=AnalysisType.RULE_BASED,
            **sample_vulnerability_data,
        )
        db_session.add(vuln)
        db_session.commit()

        retrieved = db_session.query(Vulnerability).filter_by(scan_id=scan.id).first()
        assert retrieved is not None
        assert retrieved.title == sample_vulnerability_data["title"]
        assert retrieved.severity == SeverityLevel.HIGH

    def test_vulnerability_cascade_delete(
        self, db_session: Session, sample_scan_data: dict, sample_vulnerability_data: dict
    ) -> None:
        """스캔 삭제 시 취약점 cascade 삭제 테스트."""
        scan = Scan(**sample_scan_data)
        db_session.add(scan)
        db_session.commit()

        vuln = Vulnerability(
            scan_id=scan.id,
            severity=SeverityLevel.MEDIUM,
            analysis_type=AnalysisType.LLM_BASED,
            **sample_vulnerability_data,
        )
        db_session.add(vuln)
        db_session.commit()

        # 스캔 삭제
        db_session.delete(scan)
        db_session.commit()

        # 취약점도 삭제되어야 함
        remaining = db_session.query(Vulnerability).all()
        assert len(remaining) == 0


class TestComplianceMappingModel:
    """ComplianceMapping 모델 테스트."""

    def test_create_mapping(
        self, db_session: Session, sample_scan_data: dict, sample_vulnerability_data: dict
    ) -> None:
        """컴플라이언스 매핑 생성 테스트."""
        scan = Scan(**sample_scan_data)
        db_session.add(scan)

        vuln = Vulnerability(
            scan_id=scan.id,
            severity=SeverityLevel.CRITICAL,
            analysis_type=AnalysisType.HYBRID,
            **sample_vulnerability_data,
        )
        db_session.add(vuln)
        db_session.commit()

        mapping = ComplianceMapping(
            vulnerability_id=vuln.id,
            compliance_type=ComplianceType.ISMS_P,
            compliance_id="2.10.1",
            compliance_title="입력값 검증",
            compliance_category="2.10 시스템 및 서비스 보안 관리",
        )
        db_session.add(mapping)
        db_session.commit()

        retrieved = db_session.query(ComplianceMapping).filter_by(vulnerability_id=vuln.id).first()
        assert retrieved is not None
        assert retrieved.compliance_type == ComplianceType.ISMS_P
        assert retrieved.compliance_id == "2.10.1"


class TestRuleModel:
    """Rule 모델 테스트."""

    def test_create_rule(self, db_session: Session) -> None:
        """규칙 생성 테스트."""
        rule = Rule(
            id="2.7.1-weak-crypto",
            title="취약한 암호 알고리즘 사용",
            category="2.7 암호화 적용",
            severity=SeverityLevel.HIGH,
            applicable_to=["isms", "isms-p"],
            languages=["python", "java"],
            patterns=["md5", "sha1", "DES"],
        )
        db_session.add(rule)
        db_session.commit()

        retrieved = db_session.query(Rule).filter_by(id="2.7.1-weak-crypto").first()
        assert retrieved is not None
        assert retrieved.title == "취약한 암호 알고리즘 사용"
        assert "isms" in retrieved.applicable_to


class TestConfigModel:
    """Config 모델 테스트."""

    def test_create_config(self, db_session: Session) -> None:
        """설정 생성 테스트."""
        config = Config(
            key="default_model",
            value="exaone3.5:7.8b",
            value_type="string",
            description="기본 사용 모델",
        )
        db_session.add(config)
        db_session.commit()

        retrieved = db_session.query(Config).filter_by(key="default_model").first()
        assert retrieved is not None
        assert retrieved.value == "exaone3.5:7.8b"

    def test_update_config(self, db_session: Session) -> None:
        """설정 업데이트 테스트."""
        config = Config(key="test_key", value="original")
        db_session.add(config)
        db_session.commit()

        config.value = "updated"
        db_session.commit()

        retrieved = db_session.query(Config).filter_by(key="test_key").first()
        assert retrieved.value == "updated"
