"""JSON 리포터.

표준 JSON 및 SARIF 2.1.0 형식 리포트 생성기.
"""

import json
import logging
from pathlib import Path

from anshim.core.analyzers.hybrid import HybridScanResult
from anshim.core.reporters.base import BaseReporter, ReportData

logger = logging.getLogger(__name__)

# SARIF 스펙 버전
_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


class JSONReporter(BaseReporter):
    """표준 JSON 리포트 생성기."""

    def __init__(self, sarif: bool = False) -> None:
        self.sarif = sarif

    def generate(self, scan_result: HybridScanResult, output_path: Path) -> Path:
        """JSON 리포트 파일 생성.

        Args:
            scan_result: 하이브리드 스캔 결과.
            output_path: 출력 파일 경로 (또는 디렉토리).

        Returns:
            생성된 JSON 파일 경로.
        """
        data = ReportData.from_hybrid_result(scan_result)
        ext = ".sarif" if self.sarif else ".json"

        if output_path.is_dir() or (not output_path.suffix):
            output_path.mkdir(parents=True, exist_ok=True)
            output_file = output_path / f"anshim_report_{data.scan_id}{ext}"
        else:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_file = output_path

        if self.sarif:
            report = self._build_sarif(data)
        else:
            report = self._build_json(data)

        output_file.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("JSON 리포트 생성: %s", output_file)
        return output_file

    def _build_json(self, data: ReportData) -> dict:
        """표준 JSON 구조 생성."""
        results = []
        for r in data.results:
            mappings = [
                {
                    "compliance_type": m.compliance_type,
                    "compliance_id": m.compliance_id,
                    "compliance_title": m.compliance_title,
                    "compliance_category": m.compliance_category,
                }
                for m in r.compliance_mappings
            ]
            results.append(
                {
                    "rule_id": r.rule_id,
                    "title": r.title,
                    "description": r.description,
                    "severity": r.severity,
                    "file_path": r.file_path,
                    "line_start": r.line_start,
                    "line_end": r.line_end,
                    "code_snippet": r.code_snippet,
                    "source": r.source,
                    "confidence": r.confidence,
                    "llm_analysis": r.llm_analysis,
                    "attack_scenario": r.attack_scenario,
                    "remediation": r.remediation,
                    "compliance_mappings": mappings,
                }
            )

        return {
            "schema": "anshim-report-v1",
            "scan_id": data.scan_id,
            "generated_at": data.generated_at,
            "target_path": data.target_path,
            "summary": {
                "total_files": data.total_files,
                "scanned_files": data.scanned_files,
                "duration_seconds": data.duration_seconds,
                "model_used": data.model_used,
                "compliance_types": data.compliance_types,
                "llm_enabled": data.llm_enabled,
                "false_positives_removed": data.false_positives_removed,
            },
            "statistics": {
                "total_issues": data.total_issues,
                "critical": data.critical_count,
                "high": data.high_count,
                "medium": data.medium_count,
                "low": data.low_count,
            },
            "compliance_summary": {
                stat.compliance_type: {
                    "total": stat.total,
                    "by_severity": stat.by_severity,
                }
                for stat in data.compliance_stats
            },
            "results": results,
        }

    def _build_sarif(self, data: ReportData) -> dict:
        """SARIF 2.1.0 형식 생성."""
        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
        }

        rules = []
        rule_ids_seen: set[str] = set()

        results = []
        for r in data.results:
            rule_id = r.rule_id
            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                rules.append(
                    {
                        "id": rule_id,
                        "name": r.title,
                        "shortDescription": {"text": r.title},
                        "fullDescription": {"text": r.description or r.title},
                        "help": {
                            "text": (
                                r.remediation.get("fix_summary", "")
                                if isinstance(r.remediation, dict)
                                else ""
                            )
                        },
                        "properties": {
                            "severity": r.severity,
                            "tags": list(r.compliance_types),
                        },
                    }
                )

            results.append(
                {
                    "ruleId": rule_id,
                    "level": severity_map.get(r.severity.lower(), "warning"),
                    "message": {"text": r.description or r.title},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": r.file_path.replace("\\", "/")},
                                "region": {
                                    "startLine": r.line_start,
                                    "endLine": r.line_end or r.line_start,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "source": r.source,
                        "confidence": r.confidence,
                        "compliance_mappings": [
                            f"{m.compliance_type}:{m.compliance_id}"
                            for m in r.compliance_mappings
                        ],
                    },
                }
            )

        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AnShim",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/anshim/anshim",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "scan_id": data.scan_id,
                        "target_path": data.target_path,
                        "generated_at": data.generated_at,
                    },
                }
            ],
        }
