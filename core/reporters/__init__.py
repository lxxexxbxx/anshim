"""리포트 생성 패키지 (HTML / Excel / JSON)."""

from anshim.core.reporters.base import BaseReporter, ReportData
from anshim.core.reporters.excel_reporter import ExcelReporter
from anshim.core.reporters.html_reporter import HTMLReporter
from anshim.core.reporters.json_reporter import JSONReporter

__all__ = [
    "BaseReporter",
    "ReportData",
    "HTMLReporter",
    "ExcelReporter",
    "JSONReporter",
    "get_reporter",
]


def get_reporter(fmt: str) -> BaseReporter:
    """리포터 팩토리 함수.

    Args:
        fmt: 리포트 형식 ("html", "excel", "json", "sarif").

    Returns:
        해당 형식의 리포터 인스턴스.

    Raises:
        ValueError: 지원하지 않는 형식인 경우.
    """
    fmt = fmt.lower()
    if fmt == "html":
        return HTMLReporter()
    if fmt in ("excel", "xlsx"):
        return ExcelReporter()
    if fmt == "json":
        return JSONReporter(sarif=False)
    if fmt == "sarif":
        return JSONReporter(sarif=True)
    raise ValueError(f"지원하지 않는 리포트 형식: {fmt!r}. 지원 형식: html, excel, json, sarif")
