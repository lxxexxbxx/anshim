"""FastAPI 응답 스키마 정의."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class ComplianceMappingResponse(BaseModel):
    id: int
    compliance_type: str
    compliance_id: str
    compliance_title: Optional[str] = None
    compliance_category: Optional[str] = None
    notes: Optional[str] = None


class VulnerabilityResponse(BaseModel):
    id: int
    scan_id: str
    rule_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    analysis_type: str
    is_false_positive: bool = False
    confidence: int = 100
    attack_scenario: Optional[str] = None
    remediation: Optional[str] = None
    remediation_code: Optional[str] = None
    created_at: datetime
    compliance_mappings: List[ComplianceMappingResponse] = []


class ScanResponse(BaseModel):
    id: str
    target_path: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    analysis_type: str
    model_used: Optional[str] = None
    compliance_types: Optional[List[str]] = None
    total_files: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


class ScanDetailResponse(ScanResponse):
    error_message: Optional[str] = None


class ScanListResponse(BaseModel):
    items: List[ScanResponse]
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
    recent_scans: List[ScanResponse]


class ScanCreateRequest(BaseModel):
    target_path: str
    compliance: str = "isms-p"
    model: Optional[str] = None


class ScanCreateResponse(BaseModel):
    scan_id: str
    message: str
