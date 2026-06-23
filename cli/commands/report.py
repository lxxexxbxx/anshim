"""
report 명령어 그룹 - 스캔 리포트 관리.

과거 스캔 결과 조회, 내보내기, 삭제를 수행합니다.
"""

import logging
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

app = typer.Typer(help="스캔 리포트 관리")


@app.command("list")
def list_reports(
    limit: int = typer.Option(
        10,
        "--limit",
        "-l",
        help="표시할 최대 개수",
    ),
    all_reports: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="모든 리포트 표시",
    ),
) -> None:
    """과거 스캔 결과 목록을 표시합니다."""
    from anshim.core.db.repository import ScanRepository

    repo = ScanRepository()
    effective_limit = 1000 if all_reports else limit
    scans = repo.list_scans(limit=effective_limit)

    if not scans:
        console.print("[yellow]저장된 스캔 기록이 없습니다.[/yellow]")
        console.print("[dim]anshim scan <경로> 로 첫 스캔을 시작하세요.[/dim]")
        return

    table = Table(title="스캔 기록", show_lines=False)
    table.add_column("스캔 ID", style="cyan", min_width=8, no_wrap=True)
    table.add_column("대상 경로", min_width=20, no_wrap=True)
    table.add_column("일시", min_width=16, no_wrap=True)
    table.add_column("상태", min_width=6, no_wrap=True)
    table.add_column("총계", justify="right", min_width=4, no_wrap=True)
    table.add_column("C", justify="right", min_width=4, style="red bold", no_wrap=True)
    table.add_column("H", justify="right", min_width=4, style="orange1", no_wrap=True)
    table.add_column("M", justify="right", min_width=4, style="yellow", no_wrap=True)
    table.add_column("L", justify="right", min_width=4, style="blue", no_wrap=True)

    for scan in scans:
        started = scan.started_at.strftime("%Y-%m-%d %H:%M") if scan.started_at else "-"
        status_str = {
            "completed": "[green]완료[/green]",
            "running": "[yellow]실행 중[/yellow]",
            "failed": "[red]실패[/red]",
        }.get(scan.status, scan.status)

        # 경로 앞부분 잘라내기
        path = scan.target_path or ""
        if len(path) > 34:
            path = "…" + path[-33:]

        table.add_row(
            scan.id[:8],
            path,
            started,
            status_str,
            str(scan.total_vulnerabilities or 0),
            str(scan.critical_count or 0),
            str(scan.high_count or 0),
            str(scan.medium_count or 0),
            str(scan.low_count or 0),
        )

    console.print(table)
    console.print(f"\n[dim]총 {len(scans)}개 스캔 기록[/dim]")
    console.print("[dim]상세 보기: anshim report show <스캔 ID>[/dim]")


@app.command("show")
def show_report(
    scan_id: str = typer.Argument(
        ...,
        help="스캔 ID (앞 8자리 또는 전체)",
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="브라우저 자동 열기 비활성화",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="HTML 파일 저장 경로",
    ),
) -> None:
    """특정 스캔 결과를 HTML 리포트로 열거나 재생성합니다."""
    from anshim.core.analyzers.hybrid import HybridScanResult
    from anshim.core.compliance.mapper import ComplianceMappingInfo, MappedResult
    from anshim.core.db.repository import ScanRepository, VulnerabilityRepository
    from anshim.core.reporters import get_reporter

    scan_repo = ScanRepository()
    scan = scan_repo.get_scan(scan_id)

    if not scan:
        console.print(f"[red]스캔 기록을 찾을 수 없습니다: {scan_id}[/red]")
        raise typer.Exit(1)

    console.print(f"\n[bold]스캔 결과: [cyan]{scan.id[:8]}[/cyan][/bold]")
    console.print(f"  대상: {scan.target_path}")
    console.print(f"  일시: {scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else '-'}")
    console.print(f"  상태: {scan.status}")
    console.print(f"  취약점: {scan.total_vulnerabilities or 0}개 (C:{scan.critical_count or 0} H:{scan.high_count or 0} M:{scan.medium_count or 0} L:{scan.low_count or 0})")
    console.print()

    # DB에서 취약점 조회하여 HybridScanResult 재구성
    vuln_repo = VulnerabilityRepository()
    vulns = vuln_repo.list_by_scan(scan.id)

    # MappedResult 변환
    mapped_results: list[MappedResult] = []
    for vuln in vulns:
        mappings_db = vuln_repo.get_compliance_mappings(vuln.id)
        mappings = [
            ComplianceMappingInfo(
                compliance_type=m.compliance_type.value if hasattr(m.compliance_type, "value") else str(m.compliance_type),
                compliance_id=m.compliance_id,
                compliance_title=m.compliance_title or "",
                compliance_category=m.compliance_category or "",
                rule_id=vuln.rule_id,
            )
            for m in mappings_db
        ]

        import json as _json
        attack = None
        if vuln.attack_scenario:
            try:
                attack = _json.loads(vuln.attack_scenario)
            except Exception:
                attack = {"attack_name": vuln.attack_scenario}

        remediation = None
        if vuln.remediation:
            try:
                remediation = _json.loads(vuln.remediation)
            except Exception:
                remediation = {"fix_summary": vuln.remediation}

        severity_val = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)

        mr = MappedResult(
            rule_id=vuln.rule_id,
            title=vuln.title,
            description=vuln.description or "",
            severity=severity_val,
            file_path=vuln.file_path,
            line_start=vuln.line_start,
            line_end=vuln.line_end,
            code_snippet=vuln.code_snippet,
            source="db",
            confidence=str(vuln.confidence or "medium"),
            attack_scenario=attack,
            remediation=remediation,
            compliance_mappings=mappings,
        )
        mapped_results.append(mr)

    # HybridScanResult 재구성
    result = HybridScanResult(
        scan_id=scan.id[:8],
        target_path=scan.target_path,
        total_files=0,
        scanned_files=0,
        duration_seconds=0.0,
        model_used=scan.model_used,
        compliance_types=scan.compliance_types or [],
        llm_enabled=bool(scan.model_used),
        results=mapped_results,
        total_issues=scan.total_vulnerabilities or 0,
        critical_count=scan.critical_count or 0,
        high_count=scan.high_count or 0,
        medium_count=scan.medium_count or 0,
        low_count=scan.low_count or 0,
        false_positives_removed=0,
        compliance_summary={},
    )

    # HTML 리포트 생성
    out_dir = output or Path.cwd()
    reporter = get_reporter("html")
    report_file = reporter.generate(result, out_dir)

    console.print(
        Panel(
            f"[cyan]{report_file}[/cyan]",
            title="[bold green]HTML 리포트 생성됨[/bold green]",
            border_style="green",
        )
    )

    if not no_browser:
        webbrowser.open(report_file.as_uri())
        console.print("[dim]브라우저에서 리포트를 열었습니다.[/dim]")


@app.command("export")
def export_report(
    scan_id: str = typer.Argument(
        ...,
        help="스캔 ID (앞 8자리 또는 전체)",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="출력 경로 (디렉토리)",
    ),
    excel: bool = typer.Option(
        False,
        "--excel",
        help="Excel 형식으로 내보내기",
    ),
    html: bool = typer.Option(
        False,
        "--html",
        help="HTML 형식으로 내보내기",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="JSON 형식으로 내보내기",
    ),
    sarif: bool = typer.Option(
        False,
        "--sarif",
        help="SARIF 2.1.0 형식으로 내보내기",
    ),
) -> None:
    """스캔 결과를 파일로 내보냅니다."""
    from anshim.core.analyzers.hybrid import HybridScanResult
    from anshim.core.compliance.mapper import ComplianceMappingInfo, MappedResult
    from anshim.core.db.repository import ScanRepository, VulnerabilityRepository
    from anshim.core.reporters import get_reporter

    # 기본값: 아무것도 지정 안 하면 HTML
    if not any([excel, html, json_output, sarif]):
        html = True

    scan_repo = ScanRepository()
    scan = scan_repo.get_scan(scan_id)

    if not scan:
        console.print(f"[red]스캔 기록을 찾을 수 없습니다: {scan_id}[/red]")
        raise typer.Exit(1)

    vuln_repo = VulnerabilityRepository()
    vulns = vuln_repo.list_by_scan(scan.id)

    mapped_results: list[MappedResult] = []
    for vuln in vulns:
        mappings_db = vuln_repo.get_compliance_mappings(vuln.id)
        mappings = [
            ComplianceMappingInfo(
                compliance_type=m.compliance_type.value if hasattr(m.compliance_type, "value") else str(m.compliance_type),
                compliance_id=m.compliance_id,
                compliance_title=m.compliance_title or "",
                compliance_category=m.compliance_category or "",
                rule_id=vuln.rule_id,
            )
            for m in mappings_db
        ]

        import json as _json
        attack = None
        if vuln.attack_scenario:
            try:
                attack = _json.loads(vuln.attack_scenario)
            except Exception:
                attack = {"attack_name": vuln.attack_scenario}

        remediation = None
        if vuln.remediation:
            try:
                remediation = _json.loads(vuln.remediation)
            except Exception:
                remediation = {"fix_summary": vuln.remediation}

        severity_val = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)

        mr = MappedResult(
            rule_id=vuln.rule_id,
            title=vuln.title,
            description=vuln.description or "",
            severity=severity_val,
            file_path=vuln.file_path,
            line_start=vuln.line_start,
            line_end=vuln.line_end,
            code_snippet=vuln.code_snippet,
            source="db",
            confidence=str(vuln.confidence or "medium"),
            attack_scenario=attack,
            remediation=remediation,
            compliance_mappings=mappings,
        )
        mapped_results.append(mr)

    result = HybridScanResult(
        scan_id=scan.id[:8],
        target_path=scan.target_path,
        total_files=0,
        scanned_files=0,
        duration_seconds=0.0,
        model_used=scan.model_used,
        compliance_types=scan.compliance_types or [],
        llm_enabled=bool(scan.model_used),
        results=mapped_results,
        total_issues=scan.total_vulnerabilities or 0,
        critical_count=scan.critical_count or 0,
        high_count=scan.high_count or 0,
        medium_count=scan.medium_count or 0,
        low_count=scan.low_count or 0,
        false_positives_removed=0,
        compliance_summary={},
    )

    out_dir = output or Path.cwd()
    generated: list[Path] = []

    for fmt, enabled in [("html", html), ("excel", excel), ("json", json_output), ("sarif", sarif)]:
        if not enabled:
            continue
        try:
            reporter = get_reporter(fmt)
            path = reporter.generate(result, out_dir)
            generated.append(path)
        except Exception as e:
            logger.warning("%s 리포트 생성 실패: %s", fmt, e)
            console.print(f"[yellow]{fmt.upper()} 리포트 생성 실패: {e}[/yellow]")

    if generated:
        panel_content = "\n".join(f"[cyan]{p}[/cyan]" for p in generated)
        console.print(
            Panel(
                panel_content,
                title="[bold green]내보내기 완료[/bold green]",
                border_style="green",
            )
        )


@app.command("delete")
def delete_report(
    scan_id: str = typer.Argument(
        ...,
        help="삭제할 스캔 ID",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="확인 없이 삭제",
    ),
) -> None:
    """스캔 결과를 삭제합니다."""
    from anshim.core.db.repository import ScanRepository

    if not force:
        confirm = typer.confirm(f"스캔 기록 '{scan_id}'를 삭제하시겠습니까?")
        if not confirm:
            console.print("취소되었습니다.")
            raise typer.Exit()

    repo = ScanRepository()
    deleted = repo.delete_scan(scan_id)

    if deleted:
        console.print(f"[green]스캔 기록 삭제 완료: {scan_id}[/green]")
    else:
        console.print(f"[red]스캔 기록을 찾을 수 없습니다: {scan_id}[/red]")
        raise typer.Exit(1)
