"""
scan 명령어 - 코드 보안 스캔.

디렉토리를 분석하여 보안 취약점을 탐지하고 컴플라이언스에 매핑합니다.
"""

import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from anshim.core.analyzers import LLMAnalyzer, RuleBasedAnalyzer, ScanSummary
from anshim.core.models import OllamaClient, get_recommended_model

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
    compliance: str = typer.Option(
        "isms-p",
        "--compliance",
        "-c",
        help="컴플라이언스 선택 (쉼표로 구분: isms, isms-p, owasp, cwe, all)",
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        "-m",
        help="사용할 LLM 모델 (예: exaone3.5:7.8b, qwen2.5-coder:14b)",
    ),
    output: Optional[Path] = typer.Option(
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
    severity: Optional[str] = typer.Option(
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

    console.print(f"\n[bold blue]AnShim 보안 코드 스캔[/bold blue]")
    console.print(f"대상: [cyan]{target}[/cyan]\n")

    # 컴플라이언스 파싱
    compliance_list = [c.strip().lower() for c in compliance.split(",")]
    console.print(f"컴플라이언스: [green]{', '.join(compliance_list)}[/green]")

    # 모델 결정 (지정되지 않으면 기본 추천 모델 사용)
    selected_model = model or get_recommended_model().name

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

    # 규칙 기반 분석 실행
    summary: Optional[ScanSummary] = None
    if not llm_only:
        summary = _run_rule_based_analysis(target, verbose)

        # 심각도 필터 적용
        if severity:
            summary = _filter_by_severity(summary, severity)

    # LLM 분석 실행 (rule_only가 아닌 경우)
    if not rule_only and summary and summary.results:
        summary = _run_llm_analysis(summary, selected_model, verbose)

    # 결과 출력
    if summary:
        _print_results(summary, verbose)

        # 리포트 생성 안내
        if output:
            console.print(f"\n[dim]리포트 위치: {output}[/dim]")

        # 종료 코드 결정 (critical/high 이슈 있으면 1)
        if summary.critical_count > 0 or summary.high_count > 0:
            raise typer.Exit(1)


def _run_rule_based_analysis(target: Path, verbose: bool) -> ScanSummary:
    """규칙 기반 분석 실행.

    Args:
        target: 분석 대상 경로.
        verbose: 상세 출력 여부.

    Returns:
        스캔 요약 결과.
    """
    analyzer = RuleBasedAnalyzer()

    # 분석기 상태 확인
    status = analyzer.get_status()
    if verbose:
        console.print("[dim]분석기 상태:[/dim]")
        console.print(f"  Semgrep: {'[green]사용 가능[/green]' if status['semgrep'] else '[red]미설치[/red]'}")
        console.print(f"  Bandit: {'[green]사용 가능[/green]' if status['bandit'] else '[red]미설치[/red]'}")
        console.print()

    # 분석 실행 (Progress 표시)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]규칙 기반 분석 중...", total=None)
        summary = analyzer.analyze(target)
        progress.update(task, completed=True)

    return summary


def _run_llm_analysis(
    summary: ScanSummary,
    model: str,
    verbose: bool,
) -> ScanSummary:
    """LLM 분석 실행.

    Args:
        summary: 규칙 기반 분석 결과.
        model: 사용할 LLM 모델.
        verbose: 상세 출력 여부.

    Returns:
        LLM 분석이 추가된 스캔 요약.
    """
    # Ollama 실행 확인
    client = OllamaClient()
    if not client.is_running():
        console.print("[yellow]LLM 분석 스킵 (Ollama 미실행)[/yellow]")
        console.print("[dim]Ollama 시작: ollama serve[/dim]")
        console.print()
        return summary

    # LLM 분석기 생성
    llm_analyzer = LLMAnalyzer(model=model, ollama_client=client)

    # 분석 실행 (Progress 표시)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"[cyan]LLM 심층 분석 중 ({len(summary.results)}개 취약점)...",
            total=None,
        )

        # 배치 분석 실행
        analyzed_results = llm_analyzer.analyze_batch(
            summary.results,
            max_concurrent=2,  # 동시 실행 제한
            timeout=90,  # 개별 타임아웃
        )

        progress.update(task, completed=True)

    # False Positive 필터링
    filtered_results = llm_analyzer.filter_false_positives(analyzed_results)
    fp_count = len(analyzed_results) - len(filtered_results)

    if fp_count > 0:
        console.print(f"[dim]False Positive 제거: {fp_count}개[/dim]")

    # 새로운 ScanSummary 생성
    return ScanSummary(
        target_path=summary.target_path,
        total_files=summary.total_files,
        scanned_files=summary.scanned_files,
        results=filtered_results,
        duration_seconds=summary.duration_seconds,
    )


def _filter_by_severity(summary: ScanSummary, severity: str) -> ScanSummary:
    """심각도별 필터링.

    Args:
        summary: 원본 스캔 요약.
        severity: 필터할 심각도.

    Returns:
        필터링된 스캔 요약.
    """
    severity = severity.lower()
    filtered_results = [r for r in summary.results if r.severity == severity]

    return ScanSummary(
        target_path=summary.target_path,
        total_files=summary.total_files,
        scanned_files=summary.scanned_files,
        results=filtered_results,
        duration_seconds=summary.duration_seconds,
    )


def _print_results(summary: ScanSummary, verbose: bool) -> None:
    """결과 출력.

    Args:
        summary: 스캔 요약 결과.
        verbose: 상세 출력 여부.
    """
    # 요약 통계
    console.print("\n[bold]스캔 결과 요약[/bold]")
    console.print(f"  분석 대상: {summary.target_path}")
    console.print(f"  분석된 파일: {summary.scanned_files} / {summary.total_files}")
    console.print(f"  소요 시간: {summary.duration_seconds:.2f}초")
    console.print()

    # 심각도별 통계
    stats_table = Table(show_header=False, box=None, padding=(0, 2))
    stats_table.add_column("Severity", style="bold")
    stats_table.add_column("Count", justify="right")

    stats_table.add_row(
        f"{SEVERITY_MARKER['critical']} Critical",
        f"[red bold]{summary.critical_count}[/red bold]"
    )
    stats_table.add_row(
        f"{SEVERITY_MARKER['high']} High",
        f"[orange1]{summary.high_count}[/orange1]"
    )
    stats_table.add_row(
        f"{SEVERITY_MARKER['medium']} Medium",
        f"[yellow]{summary.medium_count}[/yellow]"
    )
    stats_table.add_row(
        f"{SEVERITY_MARKER['low']} Low",
        f"[blue]{summary.low_count}[/blue]"
    )
    stats_table.add_row("", "")
    stats_table.add_row(
        "[bold]Total[/bold]",
        f"[bold]{summary.total_issues}[/bold]"
    )

    console.print(stats_table)

    # 이슈가 없으면 종료
    if summary.total_issues == 0:
        console.print("\n[green bold]취약점이 발견되지 않았습니다.[/green bold]")
        return

    # 취약점 목록 테이블
    console.print("\n[bold]발견된 취약점[/bold]")

    results_table = Table(show_header=True, header_style="bold")
    results_table.add_column("심각도", width=10)
    results_table.add_column("파일", max_width=40)
    results_table.add_column("라인", width=6, justify="right")
    results_table.add_column("규칙", max_width=30)
    results_table.add_column("설명", max_width=50)

    # 심각도 순으로 정렬 (critical > high > medium > low)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_results = sorted(
        summary.results,
        key=lambda r: severity_order.get(r.severity, 4)
    )

    # 최대 표시 개수 제한 (verbose 아닌 경우)
    max_display = len(sorted_results) if verbose else min(20, len(sorted_results))

    for result in sorted_results[:max_display]:
        color = SEVERITY_COLORS.get(result.severity, "white")

        # 파일 경로 축약
        file_path = result.file_path
        if len(file_path) > 38:
            file_path = "..." + file_path[-35:]

        # 규칙 ID 축약
        rule_id = result.rule_id
        if len(rule_id) > 28:
            rule_id = rule_id[:25] + "..."

        # 제목 축약
        title = result.title
        if len(title) > 48:
            title = title[:45] + "..."

        results_table.add_row(
            f"[{color}]{result.severity.upper()}[/{color}]",
            file_path,
            str(result.line_start),
            rule_id,
            title,
        )

    console.print(results_table)

    # 생략된 항목 안내
    if not verbose and len(sorted_results) > max_display:
        remaining = len(sorted_results) - max_display
        console.print(f"\n[dim]... {remaining}개 항목 생략 (--verbose로 전체 보기)[/dim]")

    # 코드 스니펫 및 LLM 분석 결과 출력 (verbose 모드)
    if verbose and sorted_results:
        console.print("\n[bold]상세 정보[/bold]")
        for i, result in enumerate(sorted_results[:10], 1):  # 최대 10개
            color = SEVERITY_COLORS.get(result.severity, "white")
            console.print(f"\n[{color}]#{i} [{result.severity.upper()}] {result.title}[/{color}]")
            console.print(f"   파일: {result.file_path}:{result.line_start}")
            console.print(f"   규칙: {result.rule_id}")
            console.print(f"   출처: {result.source}")

            if result.code_snippet:
                console.print("   코드:")
                for line in result.code_snippet.strip().split("\n")[:5]:
                    console.print(f"   [dim]{line}[/dim]")

            # LLM 분석 결과 출력
            llm_analysis = getattr(result, "llm_analysis", None)
            if llm_analysis:
                console.print(f"\n   [cyan]LLM 분석:[/cyan] {llm_analysis}")

            attack_scenario = getattr(result, "attack_scenario", None)
            if attack_scenario and isinstance(attack_scenario, dict):
                attack_name = attack_scenario.get("attack_name", "")
                if attack_name:
                    console.print(f"   [red]공격 유형:[/red] {attack_name}")
                attack_steps = attack_scenario.get("attack_steps", [])
                if attack_steps:
                    console.print("   [red]공격 단계:[/red]")
                    for step in attack_steps[:3]:
                        console.print(f"      - {step}")

            remediation = getattr(result, "remediation", None)
            if remediation and isinstance(remediation, dict):
                fix_summary = remediation.get("fix_summary", "")
                if fix_summary:
                    console.print(f"   [green]수정 제안:[/green] {fix_summary}")

            isms_relevance = getattr(result, "isms_relevance", None)
            if isms_relevance:
                console.print(f"   [magenta]ISMS 관련:[/magenta] {isms_relevance}")
