"""HTML 리포터.

Jinja2 기반 HTML 리포트 생성기.
"""

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from anshim.core.analyzers.hybrid import HybridScanResult
from anshim.core.reporters.base import BaseReporter, ReportData

logger = logging.getLogger(__name__)

# 템플릿 디렉토리
_TEMPLATE_DIR = Path(__file__).parent.parent.parent / "reports" / "templates"
_TEMPLATE_NAME = "report.html.j2"


class HTMLReporter(BaseReporter):
    """Jinja2 기반 HTML 리포트 생성기."""

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "j2"]),
        )
        # sort 필터에서 key 람다 허용
        self._env.globals["severity_order"] = {
            "critical": 0, "high": 1, "medium": 2, "low": 3
        }

    def generate(self, scan_result: HybridScanResult, output_path: Path) -> Path:
        """HTML 리포트 파일 생성.

        Args:
            scan_result: 하이브리드 스캔 결과.
            output_path: 출력 파일 경로 (또는 디렉토리).

        Returns:
            생성된 HTML 파일 경로.
        """
        data = ReportData.from_hybrid_result(scan_result)

        # 출력 경로 결정
        if output_path.is_dir() or (not output_path.suffix):
            output_path.mkdir(parents=True, exist_ok=True)
            output_file = output_path / f"anshim_report_{data.scan_id}.html"
        else:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_file = output_path

        # 심각도 정렬
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_results = sorted(
            data.results,
            key=lambda r: severity_order.get(r.severity.lower(), 4),
        )
        data.results = sorted_results

        template = self._env.get_template(_TEMPLATE_NAME)
        html = template.render(data=data)

        output_file.write_text(html, encoding="utf-8")
        logger.info("HTML 리포트 생성: %s", output_file)
        return output_file
