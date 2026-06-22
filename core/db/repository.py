# anshim/core/db/repository.py
"""데이터베이스 Repository 패턴 구현.

스캔 결과 및 취약점 정보의 CRUD 작업을 캡슐화합니다.
"""

import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from anshim.core.analyzers.hybrid import HybridScanResult
from anshim.core.compliance.mapper import MappedResult
from anshim.core.db.database import get_db, init_db
from anshim.core.db.models import (
    AnalysisType,
    ComplianceMapping,
    ComplianceType,
    Scan,
    SeverityLevel,
    Vulnerability,
)

logger = logging.getLogger(__name__)


class ScanRepository:
    """스캔 세션 Repository.

    스캔 메타데이터 및 상태 관리를 담당합니다.
    """

    def __init__(self, db_path: Optional[Path] = None):
        """ScanRepository 초기화.

        Args:
            db_path: 데이터베이스 파일 경로.
        """
        self.db_path = db_path
        init_db(db_path)

    def create_scan(
        self,
        target_path: str,
        model: Optional[str] = None,
        compliance_types: Optional[list[str]] = None,
        analysis_type: AnalysisType = AnalysisType.HYBRID,
    ) -> Scan:
        """새 스캔 세션 생성.

        Args:
            target_path: 스캔 대상 경로.
            model: 사용된 LLM 모델.
            compliance_types: 적용된 컴플라이언스 유형.
            analysis_type: 분석 유형.

        Returns:
            생성된 Scan 객체.
        """
        scan_id = str(uuid.uuid4())

        with get_db(self.db_path) as session:
            scan = Scan(
                id=scan_id,
                target_path=target_path,
                status="running",
                analysis_type=analysis_type,
                model_used=model,
                compliance_types=compliance_types or [],
            )
            session.add(scan)
            session.flush()

            # detach 상태에서도 사용 가능하도록 값 복사
            scan_copy = Scan(
                id=scan.id,
                target_path=scan.target_path,
                started_at=scan.started_at,
                status=scan.status,
                analysis_type=scan.analysis_type,
                model_used=scan.model_used,
                compliance_types=scan.compliance_types,
            )

        logger.info("스캔 세션 생성: %s (%s)", scan_id[:8], target_path)
        return scan_copy

    def complete_scan(
        self,
        scan_id: str,
        total_files: int,
        scanned_files: int,
        total_vulnerabilities: int,
        critical_count: int = 0,
        high_count: int = 0,
        medium_count: int = 0,
        low_count: int = 0,
    ) -> None:
        """스캔 완료 처리.

        Args:
            scan_id: 스캔 ID.
            total_files: 전체 파일 수.
            scanned_files: 스캔된 파일 수.
            total_vulnerabilities: 발견된 취약점 수.
            critical_count: Critical 이슈 수.
            high_count: High 이슈 수.
            medium_count: Medium 이슈 수.
            low_count: Low 이슈 수.
        """
        with get_db(self.db_path) as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                scan.total_files = total_files
                scan.total_vulnerabilities = total_vulnerabilities
                scan.critical_count = critical_count
                scan.high_count = high_count
                scan.medium_count = medium_count
                scan.low_count = low_count

        logger.info("스캔 완료: %s (%d개 이슈)", scan_id[:8], total_vulnerabilities)

    def fail_scan(self, scan_id: str, error_message: str) -> None:
        """스캔 실패 처리.

        Args:
            scan_id: 스캔 ID.
            error_message: 오류 메시지.
        """
        with get_db(self.db_path) as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                scan.error_message = error_message

        logger.error("스캔 실패: %s - %s", scan_id[:8], error_message)

    def get_scan(self, scan_id: str) -> Optional[Scan]:
        """스캔 조회.

        Args:
            scan_id: 스캔 ID (전체 또는 앞 8자리).

        Returns:
            Scan 객체 또는 None.
        """
        with get_db(self.db_path) as session:
            if len(scan_id) < 36:
                # 짧은 ID로 검색
                scan = (
                    session.query(Scan)
                    .filter(Scan.id.startswith(scan_id))
                    .first()
                )
            else:
                scan = session.query(Scan).filter(Scan.id == scan_id).first()

            if scan:
                # 세션 외부에서 사용 가능하도록 복사
                session.expunge(scan)
                return scan
        return None

    def list_scans(self, limit: int = 20, offset: int = 0) -> list[Scan]:
        """스캔 목록 조회.

        Args:
            limit: 최대 개수.
            offset: 건너뛸 개수.

        Returns:
            Scan 목록.
        """
        with get_db(self.db_path) as session:
            scans = (
                session.query(Scan)
                .order_by(desc(Scan.started_at))
                .offset(offset)
                .limit(limit)
                .all()
            )
            for scan in scans:
                session.expunge(scan)
            return scans

    def delete_scan(self, scan_id: str) -> bool:
        """스캔 삭제.

        Args:
            scan_id: 스캔 ID.

        Returns:
            삭제 성공 여부.
        """
        with get_db(self.db_path) as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                session.delete(scan)
                logger.info("스캔 삭제: %s", scan_id[:8])
                return True
        return False

    def get_scan_count(self) -> int:
        """전체 스캔 수 조회."""
        with get_db(self.db_path) as session:
            return session.query(func.count(Scan.id)).scalar() or 0


class VulnerabilityRepository:
    """취약점 Repository.

    취약점 데이터 저장 및 조회를 담당합니다.
    """

    def __init__(self, db_path: Optional[Path] = None):
        """VulnerabilityRepository 초기화.

        Args:
            db_path: 데이터베이스 파일 경로.
        """
        self.db_path = db_path
        init_db(db_path)

    def save_results(
        self,
        scan_id: str,
        results: list[MappedResult],
    ) -> list[Vulnerability]:
        """분석 결과 저장.

        Args:
            scan_id: 스캔 ID.
            results: 매핑된 결과 목록.

        Returns:
            저장된 Vulnerability 목록.
        """
        vulnerabilities = []

        with get_db(self.db_path) as session:
            for result in results:
                vuln = self._create_vulnerability(session, scan_id, result)
                vulnerabilities.append(vuln)

            session.flush()

            # ID 할당 후 복사
            for vuln in vulnerabilities:
                session.expunge(vuln)

        logger.info(
            "취약점 %d개 저장 완료 (scan_id: %s)",
            len(vulnerabilities),
            scan_id[:8],
        )

        return vulnerabilities

    def _create_vulnerability(
        self,
        session: Session,
        scan_id: str,
        result: MappedResult,
    ) -> Vulnerability:
        """개별 취약점 생성.

        Args:
            session: DB 세션.
            scan_id: 스캔 ID.
            result: 매핑된 결과.

        Returns:
            생성된 Vulnerability 객체.
        """
        # 심각도 변환
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        severity = severity_map.get(
            result.severity.lower(),
            SeverityLevel.MEDIUM,
        )

        # 분석 유형 결정
        analysis_type = AnalysisType.RULE_BASED
        if result.llm_analysis:
            analysis_type = AnalysisType.HYBRID

        # 공격 시나리오를 문자열로 변환
        attack_scenario_str = None
        if result.attack_scenario:
            import json
            attack_scenario_str = json.dumps(result.attack_scenario, ensure_ascii=False)

        # 수정 제안을 문자열로 변환
        remediation_str = None
        remediation_code = None
        if result.remediation:
            if isinstance(result.remediation, dict):
                import json
                remediation_str = json.dumps(result.remediation, ensure_ascii=False)
                remediation_code = result.remediation.get("fixed_code", "")
            else:
                remediation_str = str(result.remediation)

        # Vulnerability 생성
        vuln = Vulnerability(
            scan_id=scan_id,
            rule_id=result.rule_id,
            title=result.title,
            description=result.description,
            severity=severity,
            file_path=result.file_path,
            line_start=result.line_start,
            line_end=result.line_end,
            code_snippet=result.code_snippet,
            analysis_type=analysis_type,
            is_false_positive=result.is_false_positive,
            confidence=self._parse_confidence(result.confidence),
            attack_scenario=attack_scenario_str,
            remediation=remediation_str,
            remediation_code=remediation_code,
        )

        session.add(vuln)
        session.flush()  # ID 할당

        # 컴플라이언스 매핑 추가
        for mapping_info in result.compliance_mappings:
            comp_type_map = {
                "isms": ComplianceType.ISMS,
                "isms-p": ComplianceType.ISMS_P,
                "owasp": ComplianceType.OWASP,
                "cwe": ComplianceType.CWE,
            }
            comp_type = comp_type_map.get(
                mapping_info.compliance_type.lower(),
                ComplianceType.ISMS_P,
            )

            mapping = ComplianceMapping(
                vulnerability_id=vuln.id,
                compliance_type=comp_type,
                compliance_id=mapping_info.compliance_id,
                compliance_title=mapping_info.compliance_title,
                compliance_category=mapping_info.compliance_category,
                notes=mapping_info.remediation_ko or "",
            )
            session.add(mapping)

        return vuln

    def _parse_confidence(self, confidence: str) -> int:
        """신뢰도 문자열을 정수로 변환.

        Args:
            confidence: 신뢰도 문자열 (high, medium, low).

        Returns:
            0-100 사이 정수.
        """
        confidence_map = {"high": 90, "medium": 70, "low": 50}
        if isinstance(confidence, int):
            return confidence
        return confidence_map.get(confidence.lower(), 70)

    def list_by_scan(self, scan_id: str) -> list[Vulnerability]:
        """스캔별 취약점 목록 조회.

        Args:
            scan_id: 스캔 ID.

        Returns:
            Vulnerability 목록.
        """
        with get_db(self.db_path) as session:
            # 짧은 ID 지원
            if len(scan_id) < 36:
                vulnerabilities = (
                    session.query(Vulnerability)
                    .join(Scan)
                    .filter(Scan.id.startswith(scan_id))
                    .order_by(Vulnerability.severity, Vulnerability.file_path)
                    .all()
                )
            else:
                vulnerabilities = (
                    session.query(Vulnerability)
                    .filter(Vulnerability.scan_id == scan_id)
                    .order_by(Vulnerability.severity, Vulnerability.file_path)
                    .all()
                )

            for vuln in vulnerabilities:
                session.expunge(vuln)
            return vulnerabilities

    def list_by_severity(
        self,
        scan_id: str,
        severity: str,
    ) -> list[Vulnerability]:
        """심각도별 취약점 조회.

        Args:
            scan_id: 스캔 ID.
            severity: 심각도 문자열.

        Returns:
            Vulnerability 목록.
        """
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
        }
        sev_level = severity_map.get(severity.lower())
        if not sev_level:
            return []

        with get_db(self.db_path) as session:
            vulnerabilities = (
                session.query(Vulnerability)
                .filter(Vulnerability.scan_id == scan_id)
                .filter(Vulnerability.severity == sev_level)
                .order_by(Vulnerability.file_path)
                .all()
            )

            for vuln in vulnerabilities:
                session.expunge(vuln)
            return vulnerabilities

    def get_vulnerability(self, vuln_id: int) -> Optional[Vulnerability]:
        """취약점 조회.

        Args:
            vuln_id: 취약점 ID.

        Returns:
            Vulnerability 객체 또는 None.
        """
        with get_db(self.db_path) as session:
            vuln = (
                session.query(Vulnerability)
                .filter(Vulnerability.id == vuln_id)
                .first()
            )
            if vuln:
                session.expunge(vuln)
            return vuln

    def get_compliance_mappings(
        self,
        vuln_id: int,
    ) -> list[ComplianceMapping]:
        """취약점의 컴플라이언스 매핑 조회.

        Args:
            vuln_id: 취약점 ID.

        Returns:
            ComplianceMapping 목록.
        """
        with get_db(self.db_path) as session:
            mappings = (
                session.query(ComplianceMapping)
                .filter(ComplianceMapping.vulnerability_id == vuln_id)
                .all()
            )
            for m in mappings:
                session.expunge(m)
            return mappings


def save_hybrid_result(
    result: HybridScanResult,
    db_path: Optional[Path] = None,
) -> str:
    """HybridScanResult를 DB에 저장.

    Args:
        result: 하이브리드 스캔 결과.
        db_path: DB 파일 경로.

    Returns:
        저장된 스캔 ID.
    """
    scan_repo = ScanRepository(db_path)
    vuln_repo = VulnerabilityRepository(db_path)

    # 분석 유형 결정
    analysis_type = AnalysisType.HYBRID if result.llm_enabled else AnalysisType.RULE_BASED

    # 스캔 생성
    scan = scan_repo.create_scan(
        target_path=result.target_path,
        model=result.model_used,
        compliance_types=result.compliance_types,
        analysis_type=analysis_type,
    )

    try:
        # 취약점 저장
        vuln_repo.save_results(scan.id, result.results)

        # 스캔 완료 처리
        scan_repo.complete_scan(
            scan_id=scan.id,
            total_files=result.total_files,
            scanned_files=result.scanned_files,
            total_vulnerabilities=result.total_issues,
            critical_count=result.critical_count,
            high_count=result.high_count,
            medium_count=result.medium_count,
            low_count=result.low_count,
        )

        logger.info("스캔 결과 DB 저장 완료: %s", scan.id[:8])
        return scan.id

    except Exception as e:
        scan_repo.fail_scan(scan.id, str(e))
        raise
