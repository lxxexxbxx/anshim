"""FastAPI 웹 API 서버."""

import logging
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from anshim.core.api.schemas import (
    ComplianceMappingResponse,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanDetailResponse,
    ScanListResponse,
    ScanResponse,
    SeverityStats,
    StatsResponse,
    VulnerabilityResponse,
)
from anshim.core.db.repository import ScanRepository, VulnerabilityRepository

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AnShim API",
    description="안심 - 로컬 LLM 기반 보안 코드 감사 도구 API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _scan_to_response(scan) -> ScanResponse:
    return ScanResponse(
        id=scan.id,
        target_path=scan.target_path,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        status=scan.status,
        analysis_type=scan.analysis_type.value if hasattr(scan.analysis_type, "value") else scan.analysis_type,
        model_used=scan.model_used,
        compliance_types=scan.compliance_types or [],
        total_files=scan.total_files or 0,
        total_vulnerabilities=scan.total_vulnerabilities or 0,
        critical_count=scan.critical_count or 0,
        high_count=scan.high_count or 0,
        medium_count=scan.medium_count or 0,
        low_count=scan.low_count or 0,
    )


def _vuln_to_response(vuln, mappings=None) -> VulnerabilityResponse:
    mapping_responses = []
    if mappings:
        for m in mappings:
            mapping_responses.append(
                ComplianceMappingResponse(
                    id=m.id,
                    compliance_type=m.compliance_type.value if hasattr(m.compliance_type, "value") else m.compliance_type,
                    compliance_id=m.compliance_id,
                    compliance_title=m.compliance_title,
                    compliance_category=m.compliance_category,
                    notes=m.notes,
                )
            )

    return VulnerabilityResponse(
        id=vuln.id,
        scan_id=vuln.scan_id,
        rule_id=vuln.rule_id,
        title=vuln.title,
        description=vuln.description,
        severity=vuln.severity.value if hasattr(vuln.severity, "value") else vuln.severity,
        file_path=vuln.file_path,
        line_start=vuln.line_start,
        line_end=vuln.line_end,
        code_snippet=vuln.code_snippet,
        analysis_type=vuln.analysis_type.value if hasattr(vuln.analysis_type, "value") else vuln.analysis_type,
        is_false_positive=vuln.is_false_positive or False,
        confidence=vuln.confidence or 100,
        attack_scenario=vuln.attack_scenario,
        remediation=vuln.remediation,
        remediation_code=vuln.remediation_code,
        created_at=vuln.created_at,
        compliance_mappings=mapping_responses,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "service": "anshim-api"}


@app.get("/api/scans", response_model=ScanListResponse)
async def list_scans(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> ScanListResponse:
    repo = ScanRepository()
    scans = repo.list_scans(limit=limit, offset=offset)
    total = repo.get_scan_count()
    return ScanListResponse(
        items=[_scan_to_response(s) for s in scans],
        total=total,
    )


@app.get("/api/scans/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: str) -> ScanDetailResponse:
    repo = ScanRepository()
    scan = repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="스캔을 찾을 수 없습니다")

    base = _scan_to_response(scan)
    return ScanDetailResponse(
        **base.model_dump(),
        error_message=scan.error_message,
    )


@app.get("/api/scans/{scan_id}/vulnerabilities", response_model=list[VulnerabilityResponse])
async def list_vulnerabilities(
    scan_id: str,
    severity: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[VulnerabilityResponse]:
    scan_repo = ScanRepository()
    scan = scan_repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="스캔을 찾을 수 없습니다")

    vuln_repo = VulnerabilityRepository()
    if severity:
        vulns = vuln_repo.list_by_severity(scan.id, severity)
    else:
        vulns = vuln_repo.list_by_scan(scan.id)

    result = []
    for vuln in vulns[offset : offset + limit]:
        mappings = vuln_repo.get_compliance_mappings(vuln.id)
        result.append(_vuln_to_response(vuln, mappings))

    return result


@app.get("/api/scans/{scan_id}/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(scan_id: str, vuln_id: int) -> VulnerabilityResponse:
    scan_repo = ScanRepository()
    scan = scan_repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="스캔을 찾을 수 없습니다")

    vuln_repo = VulnerabilityRepository()
    vuln = vuln_repo.get_vulnerability(vuln_id)
    if not vuln or vuln.scan_id != scan.id:
        raise HTTPException(status_code=404, detail="취약점을 찾을 수 없습니다")

    mappings = vuln_repo.get_compliance_mappings(vuln_id)
    return _vuln_to_response(vuln, mappings)


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    repo = ScanRepository()
    scan = repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="스캔을 찾을 수 없습니다")

    repo.delete_scan(scan.id)
    return {"message": "스캔이 삭제되었습니다"}


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats() -> StatsResponse:
    scan_repo = ScanRepository()
    total_scans = scan_repo.get_scan_count()
    all_scans = scan_repo.list_scans(limit=1000)

    total_vulnerabilities = sum(s.total_vulnerabilities or 0 for s in all_scans)
    critical = sum(s.critical_count or 0 for s in all_scans)
    high = sum(s.high_count or 0 for s in all_scans)
    medium = sum(s.medium_count or 0 for s in all_scans)
    low = sum(s.low_count or 0 for s in all_scans)

    recent = scan_repo.list_scans(limit=5)

    return StatsResponse(
        total_scans=total_scans,
        total_vulnerabilities=total_vulnerabilities,
        severity_distribution=SeverityStats(
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            info=0,
        ),
        recent_scans=[_scan_to_response(s) for s in recent],
    )


@app.post("/api/scans", response_model=ScanCreateResponse)
async def create_scan(
    request: ScanCreateRequest,
    background_tasks: BackgroundTasks,
) -> ScanCreateResponse:
    """새 스캔 시작 (비동기 백그라운드 실행)."""
    target = Path(request.target_path)
    if not target.exists():
        raise HTTPException(status_code=400, detail=f"경로가 존재하지 않습니다: {request.target_path}")

    from anshim.core.db.repository import ScanRepository as _SR

    repo = _SR()
    from anshim.core.db.models import AnalysisType

    scan = repo.create_scan(
        target_path=request.target_path,
        model=request.model,
        compliance_types=[request.compliance],
        analysis_type=AnalysisType.HYBRID,
    )

    def _run_scan(scan_id: str, target_path: str, compliance: str, model: str | None):
        try:
            from anshim.core.analyzers.hybrid import HybridAnalyzer
            from anshim.core.db.repository import save_hybrid_result

            analyzer = HybridAnalyzer(
                compliance_types=[compliance],
                model=model,
            )
            result = analyzer.analyze(Path(target_path))
            save_hybrid_result(result)
        except Exception as exc:
            logger.error("백그라운드 스캔 실패 (%s): %s", scan_id[:8], exc)
            repo.fail_scan(scan_id, str(exc))

    background_tasks.add_task(_run_scan, scan.id, request.target_path, request.compliance, request.model)

    return ScanCreateResponse(
        scan_id=scan.id,
        message="스캔이 시작되었습니다. /api/scans/{scan_id}로 진행 상황을 확인하세요.",
    )
