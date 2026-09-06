"""FastAPI 응답 스키마 정의."""

from datetime import datetime

from pydantic import BaseModel


class ComplianceMappingResponse(BaseModel):
    id: int
    compliance_type: str
    compliance_id: str
    compliance_title: str | None = None
    compliance_category: str | None = None
    notes: str | None = None


class VulnerabilityResponse(BaseModel):
    id: int
    scan_id: str
    rule_id: str | None = None
    title: str
    description: str | None = None
    severity: str
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    code_snippet: str | None = None
    analysis_type: str
    is_false_positive: bool = False
    confidence: int = 100
    attack_scenario: str | None = None
    remediation: str | None = None
    remediation_code: str | None = None
    created_at: datetime
    compliance_mappings: list[ComplianceMappingResponse] = []


class ScanResponse(BaseModel):
    id: str
    target_path: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str
    analysis_type: str
    model_used: str | None = None
    compliance_types: list[str] | None = None
    total_files: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


class ScanDetailResponse(ScanResponse):
    error_message: str | None = None


class ScanListResponse(BaseModel):
    items: list[ScanResponse]
    total: int


class SeverityStats(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class DailyCount(BaseModel):
    date: str
    count: int


class StatsResponse(BaseModel):
    total_scans: int
    total_vulnerabilities: int
    severity_distribution: SeverityStats
    recent_scans: list[ScanResponse]


class ScanCreateRequest(BaseModel):
    target_path: str
    compliance: str = "isms-p"
    model: str | None = None


class ScanCreateResponse(BaseModel):
    scan_id: str
    message: str
