"""
scan 명령어 - 코드 보안 스캔.

디렉토리를 분석하여 보안 취약점을 탐지하고 컴플라이언스에 매핑합니다.
"""

import logging
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from anshim.core.analyzers import HybridAnalyzer, HybridScanResult
from anshim.core.db import save_hybrid_result
from anshim.core.models import get_recommended_model
from anshim.core.reporters import get_reporter
from anshim.core.utils.config_manager import get_config

logger = logging.getLogger(__name__)
console = Console()

# 심각도별 색상 매핑
SEVERITY_COLORS: dict[str, str] = {
    "critical": "red bold",
    "high": "orange1",
    "medium": "yellow",
    "low": "blue",
}

# 심각도별 표시
SEVERITY_MARKER: dict[str, str] = {
    "critical": "[red]*[/red]",
    "high": "[orange1]*[/orange1]",
    "medium": "[yellow]*[/yellow]",
    "low": "[blue]*[/blue]",
}


def scan_command(
    target: Path = typer.Argument(
        ...,
        help="스캔할 디렉토리 경로",
        exists=True,
        file_okay=True,
        dir_okay=True,
        resolve_path=True,
    ),
    compliance: str | None = typer.Option(
        None,
        "--compliance",
        "-c",
        help="컴플라이언스 선택 (쉼표로 구분: isms, isms-p, owasp, cwe, all). 미지정 시 config.yaml 기본값 사용",
    ),
    model: str | None = typer.Option(
        None,
        "--model",
        "-m",
        help="사용할 LLM 모델. 미지정 시 config.yaml 기본값 사용",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="리포트 출력 디렉토리",
    ),
    excel: bool = typer.Option(
        False,
        "--excel",
        help="Excel 리포트 생성",
    ),
    html: bool = typer.Option(
        True,
        "--html/--no-html",
        help="HTML 리포트 생성 (기본값: True)",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="JSON 리포트 생성",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help="심각도 필터 (critical, high, medium, low)",
    ),
    rule_only: bool = typer.Option(
        False,
        "--rule-only",
        help="규칙 기반 분석만 수행 (LLM 분석 제외)",
    ),
    llm_only: bool = typer.Option(
        False,
        "--llm-only",
        help="LLM 분석만 수행 (규칙 기반 분석 제외)",
    ),
    no_db: bool = typer.Option(
        False,
        "--no-db",
        help="DB 저장 건너뛰기",
    ),
    open_report: bool = typer.Option(
        False,
        "--open",
        help="스캔 완료 후 HTML 리포트를 브라우저로 자동 오픈",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="상세 출력",
    ),
) -> None:
    """
    디렉토리를 스캔하여 보안 취약점을 분석합니다.

    기본적으로 하이브리드 분석 (규칙 기반 + LLM)을 수행하며,
    선택한 컴플라이언스에 따라 결과를 매핑합니다.
    """
    # 로깅 레벨 설정
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # config.yaml에서 기본값 읽기 (CLI 플래그 > config > 하드코딩 기본값)
    cfg = get_config()

    console.print("\n[bold blue]AnShim 보안 코드 스캔[/bold blue]")
    console.print(f"대상: [cyan]{target}[/cyan]\n")

    # 컴플라이언스 파싱 (CLI 미지정 시 config 기본값)
    effective_compliance = compliance or cfg.compliance
    compliance_list = [c.strip().lower() for c in effective_compliance.split(",")]
    console.print(f"컴플라이언스: [green]{', '.join(compliance_list)}[/green]")

    # 모델 결정 (CLI 미지정 시 config > 추천 모델 순)
    selected_model = model or cfg.model or get_recommended_model().name

    # 분석 모드 표시
    if rule_only:
        console.print("분석 모드: [yellow]규칙 기반만 (Semgrep/Bandit)[/yellow]")
    elif llm_only:
        console.print("분석 모드: [yellow]LLM만[/yellow]")
        console.print(f"LLM 모델: [cyan]{selected_model}[/cyan]")
    else:
        console.print("분석 모드: [yellow]하이브리드 (규칙 + LLM)[/yellow]")
        console.print(f"LLM 모델: [cyan]{selected_model}[/cyan]")

    console.print()

    # HybridAnalyzer 생성
    analyzer = HybridAnalyzer(
        model=selected_model,
        compliance_types=compliance_list,
    )

    # 분석기 상태 확인
    status = analyzer.get_status()
    if not rule_only:
        if not status.get("semgrep"):
            console.print("[yellow]⚠ Semgrep 미설치: pip install semgrep[/yellow]")
        if not status.get("bandit"):
            console.print("[yellow]⚠ Bandit 미설치: pip install bandit[/yellow]")
        if not status.get("ollama") and not rule_only:
            console.print("[yellow]⚠ Ollama 미실행: ollama serve 로 시작 후 LLM 분석 가능[/yellow]")

    if verbose:
        console.print("[dim]분석기 상태:[/dim]")
        console.print(f"  Semgrep: {'[green]사용 가능[/green]' if status.get('semgrep') else '[red]미설치[/red]'}")
        console.print(f"  Bandit: {'[green]사용 가능[/green]' if status.get('bandit') else '[red]미설치[/red]'}")
        console.print(f"  Ollama: {'[green]실행 중[/green]' if status.get('ollama') else '[yellow]미실행[/yellow]'}")
        console.print()

    # 하이브리드 분석 실행
    result = _run_hybrid_analysis(
        analyzer=analyzer,
        target=target,
        skip_llm=rule_only,
        verbose=verbose,
    )

    # 심각도 필터 적용
    if severity:
        result = result.filter_by_severity(severity)
        console.print(f"[dim]심각도 필터 적용: {severity}[/dim]")

    # DB 저장
    scan_id = result.scan_id
    if not no_db:
        try:
            scan_id = save_hybrid_result(result)
            console.print(f"\n[dim]스캔 ID: [cyan]{scan_id[:8]}[/cyan] — anshim report show {scan_id[:8]}[/dim]")
        except Exception as e:
            logger.warning("DB 저장 실패: %s", e)
            console.print(f"[yellow]DB 저장 실패: {e}[/yellow]")

    # 결과 출력
    _print_results(result, verbose)

    # 리포트 생성
    generated = _generate_reports(
        result=result,
        scan_id=scan_id,
        output=output,
        html=html,
        excel=excel,
        json_output=json_output,
    )

    # --open: HTML 리포트 브라우저 자동 오픈
    if open_report and generated:
        html_reports = [p for p in generated if p.suffix == ".html"]
        if html_reports:
            webbrowser.open(html_reports[0].as_uri())

    # 종료 코드 결정 (critical/high 이슈 있으면 1)
    if result.critical_count > 0 or result.high_count > 0:
        raise typer.Exit(1)


def _run_hybrid_analysis(
    analyzer: HybridAnalyzer,
    target: Path,
    skip_llm: bool,
    verbose: bool,
) -> HybridScanResult:
    """하이브리드 분석 실행.

    Args:
        analyzer: 하이브리드 분석기.
        target: 분석 대상 경로.
        skip_llm: LLM 분석 스킵 여부.
        verbose: 상세 출력 여부.

    Returns:
        하이브리드 스캔 결과.
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]분석 중...", total=100)

        def update_progress(stage: str, pct: float):
            progress.update(task, description=f"[cyan]{stage}", completed=int(pct * 100))

        result = analyzer.analyze(
            target=target,
            skip_llm=skip_llm,
            llm_timeout=90,
            progress_callback=update_progress,
        )

        progress.update(task, completed=100)

    # LLM 분석 여부 및 FP 제거 수 표시
    if result.llm_enabled:
        console.print(f"[dim]LLM 분석 완료 (모델: {result.model_used})[/dim]")
        if result.false_positives_removed > 0:
            console.print(f"[dim]False Positive 제거: {result.false_positives_removed}개[/dim]")
    elif not skip_llm:
        console.print("[yellow]LLM 분석 스킵 (Ollama 미실행)[/yellow]")
        console.print("[dim]Ollama 시작: ollama serve[/dim]")

    return result


def _print_results(result: HybridScanResult, verbose: bool) -> None:
    """결과 출력.

    Args:
        result: 하이브리드 스캔 결과.
        verbose: 상세 출력 여부.
    """
    # 요약 통계
    console.print("\n[bold]스캔 결과 요약[/bold]")
    console.print(f"  분석 대상: {result.target_path}")
    console.print(f"  분석된 파일: {result.scanned_files} / {result.total_files}")
    console.print(f"  소요 시간: {result.duration_seconds:.2f}초")
    console.print()

    # 심각도별 통계
    stats_table = Table(show_header=False, box=None, padding=(0, 2))
    stats_table.add_column("Severity", style="bold")
    stats_table.add_column("Count", justify="right")

    stats_table.add_row(
        f"{SEVERITY_MARKER['critical']} Critical",
        f"[red bold]{result.critical_count}[/red bold]"
    )
    stats_table.add_row(
        f"{SEVERITY_MARKER['high']} High",
        f"[orange1]{result.high_count}[/orange1]"
    )
    stats_table.add_row(
        f"{SEVERITY_MARKER['medium']} Medium",
        f"[yellow]{result.medium_count}[/yellow]"
    )
    stats_table.add_row(
        f"{SEVERITY_MARKER['low']} Low",
        f"[blue]{result.low_count}[/blue]"
    )
    stats_table.add_row("", "")
    stats_table.add_row(
        "[bold]Total[/bold]",
        f"[bold]{result.total_issues}[/bold]"
    )

    console.print(stats_table)

    # 컴플라이언스별 통계 출력
    if result.compliance_summary:
        console.print("\n[bold]컴플라이언스별 통계[/bold]")
        for comp_type, stats in result.compliance_summary.items():
            if stats["total"] > 0:
                console.print(f"  {comp_type.upper()}: {stats['total']}개")

    # 이슈가 없으면 종료
    if result.total_issues == 0:
        console.print("\n[green bold]취약점이 발견되지 않았습니다.[/green bold]")
        return

    # 취약점 목록 테이블
    console.print("\n[bold]발견된 취약점[/bold]")

    results_table = Table(show_header=True, header_style="bold")
    results_table.add_column("심각도", width=10)
    results_table.add_column("파일", max_width=40)
    results_table.add_column("라인", width=6, justify="right")
    results_table.add_column("규칙", max_width=30)
    results_table.add_column("컴플라이언스", max_width=20)

    # 심각도 순으로 정렬 (critical > high > medium > low)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_results = sorted(
        result.results,
        key=lambda r: severity_order.get(r.severity.lower(), 4)
    )

    # 최대 표시 개수 제한 (verbose 아닌 경우)
    max_display = len(sorted_results) if verbose else min(20, len(sorted_results))

    for res in sorted_results[:max_display]:
        color = SEVERITY_COLORS.get(res.severity.lower(), "white")

        # 파일 경로 축약
        file_path = res.file_path
        if len(file_path) > 38:
            file_path = "..." + file_path[-35:]

        # 규칙 ID 축약
        rule_id = res.rule_id
        if len(rule_id) > 28:
            rule_id = rule_id[:25] + "..."

        # 컴플라이언스 매핑 표시
        compliance_str = ""
        if res.compliance_mappings:
            comp_types = list({m.compliance_type.upper() for m in res.compliance_mappings})[:2]
            compliance_str = ", ".join(comp_types)

        results_table.add_row(
            f"[{color}]{res.severity.upper()}[/{color}]",
            file_path,
            str(res.line_start),
            rule_id,
            compliance_str,
        )

    console.print(results_table)

    # 생략된 항목 안내
    if not verbose and len(sorted_results) > max_display:
        remaining = len(sorted_results) - max_display
        console.print(f"\n[dim]... {remaining}개 항목 생략 (--verbose로 전체 보기)[/dim]")

    # 코드 스니펫 및 LLM 분석 결과 출력 (verbose 모드)
    if verbose and sorted_results:
        console.print("\n[bold]상세 정보[/bold]")
        for i, res in enumerate(sorted_results[:10], 1):  # 최대 10개
            color = SEVERITY_COLORS.get(res.severity.lower(), "white")
            console.print(f"\n[{color}]#{i} [{res.severity.upper()}] {res.title}[/{color}]")
            console.print(f"   파일: {res.file_path}:{res.line_start}")
            console.print(f"   규칙: {res.rule_id}")
            console.print(f"   출처: {res.source}")

            # 컴플라이언스 매핑 상세
            if res.compliance_mappings:
                console.print("   컴플라이언스 매핑:")
                for mapping in res.compliance_mappings[:3]:
                    console.print(
                        f"      - [{mapping.compliance_type.upper()}] "
                        f"{mapping.compliance_id}: {mapping.compliance_title}"
                    )

            if res.code_snippet:
                console.print("   코드:")
                for line in res.code_snippet.strip().split("\n")[:5]:
                    console.print(f"   [dim]{line}[/dim]")

            # LLM 분석 결과 출력
            if res.llm_analysis:
                console.print(f"\n   [cyan]LLM 분석:[/cyan] {res.llm_analysis}")

            if res.attack_scenario and isinstance(res.attack_scenario, dict):
                attack_name = res.attack_scenario.get("attack_name", "")
                if attack_name:
                    console.print(f"   [red]공격 유형:[/red] {attack_name}")
                attack_steps = res.attack_scenario.get("attack_steps", [])
                if attack_steps:
                    console.print("   [red]공격 단계:[/red]")
                    for step in attack_steps[:3]:
                        console.print(f"      - {step}")

            if res.remediation and isinstance(res.remediation, dict):
                fix_summary = res.remediation.get("fix_summary", "")
                if fix_summary:
                    console.print(f"   [green]수정 제안:[/green] {fix_summary}")

            if res.isms_relevance:
                console.print(f"   [magenta]ISMS 관련:[/magenta] {res.isms_relevance}")


def _generate_reports(
    result: HybridScanResult,
    scan_id: str,
    output: Path | None,
    html: bool,
    excel: bool,
    json_output: bool,
) -> list[Path]:
    """스캔 결과를 파일 리포트로 저장.

    Args:
        result: 스캔 결과.
        scan_id: DB 저장된 스캔 ID.
        output: 출력 디렉토리.
        html: HTML 생성 여부.
        excel: Excel 생성 여부.
        json_output: JSON 생성 여부.

    Returns:
        생성된 리포트 파일 경로 목록.
    """
    out_dir = output or Path.cwd()
    generated: list[Path] = []

    formats: list[tuple[str, bool]] = [
        ("html", html),
        ("excel", excel),
        ("json", json_output),
    ]

    for fmt, enabled in formats:
        if not enabled:
            continue
        try:
            reporter = get_reporter(fmt)
            report_path = reporter.generate(result, out_dir)
            generated.append(report_path)
        except Exception as e:
            logger.warning("%s 리포트 생성 실패: %s", fmt.upper(), e)
            console.print(f"[yellow]{fmt.upper()} 리포트 생성 실패: {e}[/yellow]")

    if generated:
        console.print()
        panel_content = "\n".join(f"[cyan]{p}[/cyan]" for p in generated)
        console.print(
            Panel(
                panel_content,
                title="[bold green]리포트 생성 완료[/bold green]",
                border_style="green",
            )
        )

    return generated
