"""explain 명령어 - 특정 취약점의 공격 시나리오와 수정 제안 생성.

스캔 경로에서 분리된 명령이다. 시나리오와 수정 제안 생성은 취약점 1건당 LLM을
2회 더 호출하고 긴 서술을 만들어야 해서, 스캔 전체에 적용하면 시간이 수 배로
늘어난다. 사용자가 실제로 들여다볼 취약점을 지목했을 때만 생성한다.
"""

import logging

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from anshim.core.analyzers.models import AnalysisResult

logger = logging.getLogger(__name__)
console = Console()


def _to_analysis_result(vuln) -> AnalysisResult:  # noqa: ANN001
    """DB의 Vulnerability 레코드를 AnalysisResult로 변환합니다.

    Args:
        vuln: Vulnerability ORM 인스턴스.

    Returns:
        LLM 분석기에 넘길 AnalysisResult.
    """
    severity = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)
    return AnalysisResult(
        rule_id=vuln.rule_id or "unknown",
        title=vuln.title,
        description=vuln.description or "",
        severity=severity,
        file_path=vuln.file_path,
        line_start=vuln.line_start or 1,
        line_end=vuln.line_end,
        code_snippet=vuln.code_snippet,
        source=vuln.analysis_type.value
        if hasattr(vuln.analysis_type, "value")
        else str(vuln.analysis_type),
    )


def _print_vulnerability_list(vulns: list) -> None:
    """취약점 목록을 ID와 함께 출력합니다.

    Args:
        vulns: Vulnerability 목록.
    """
    table = Table(title="취약점 목록 (ID를 --vuln 으로 지정하세요)")
    table.add_column("ID", justify="right", style="cyan")
    table.add_column("심각도", style="magenta")
    table.add_column("파일", overflow="fold")
    table.add_column("라인", justify="right")
    table.add_column("규칙")
    table.add_column("설명 생성됨", justify="center")

    for v in vulns:
        severity = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
        done = "O" if v.attack_scenario else "-"
        table.add_row(
            str(v.id),
            severity.upper(),
            v.file_path,
            str(v.line_start or "-"),
            (v.rule_id or "-")[:34],
            done,
        )
    console.print(table)


def _format_value(value: object, indent: int = 0) -> str:
    """LLM이 반환한 값을 사람이 읽을 수 있게 정리합니다.

    모델은 문자열, 문자열 목록, 중첩 딕셔너리를 섞어서 반환합니다.
    그대로 출력하면 파이썬 repr 이 노출되므로 형태별로 풀어 씁니다.

    Args:
        value: 출력할 값.
        indent: 들여쓰기 깊이.

    Returns:
        출력용 문자열.
    """
    pad = "  " * indent
    if isinstance(value, list):
        return "\n".join(f"{pad}- {_format_value(v, indent + 1).lstrip()}" for v in value)
    if isinstance(value, dict):
        rendered = []
        for key, item in value.items():
            formatted = _format_value(item, indent + 1)
            if isinstance(item, (list, dict)):
                # 목록과 중첩 딕셔너리는 줄을 바꿔야 계층이 보인다.
                rendered.append(f"{pad}[bold]{key}[/bold]:\n{formatted}")
            else:
                # 스칼라는 같은 줄에 붙이므로 들여쓰기를 제거한다.
                rendered.append(f"{pad}[bold]{key}[/bold]: {formatted.lstrip()}")
        return "\n".join(rendered)
    return f"{pad}{value}"


def _render_section(data: dict, title: str, style: str) -> None:
    """생성 결과 한 섹션을 출력합니다.

    Args:
        data: 출력할 딕셔너리.
        title: 패널 제목.
        style: 테두리 색상.
    """
    body = "\n\n".join(f"[bold]{k}[/bold]\n{_format_value(v, 1)}" for k, v in data.items())
    console.print(Panel(body, title=title, border_style=style))


def _render_explanation(vuln, explanation: dict) -> None:  # noqa: ANN001
    """생성된 설명을 출력합니다.

    Args:
        vuln: 대상 Vulnerability.
        explanation: explain_vulnerability 결과.
    """
    console.print(
        Panel(
            f"[bold]{vuln.title}[/bold]\n"
            f"{vuln.file_path}:{vuln.line_start}  ({vuln.rule_id or '-'})",
            title=f"취약점 #{vuln.id}",
        )
    )

    attack = explanation.get("attack_scenario")
    if attack:
        _render_section(attack, "공격 시나리오", "red")
    else:
        console.print("[yellow]공격 시나리오를 생성하지 못했습니다.[/yellow]")

    fix = explanation.get("remediation")
    if fix:
        _render_section(fix, "수정 제안", "green")
    else:
        console.print("[yellow]수정 제안을 생성하지 못했습니다.[/yellow]")


def explain_command(
    scan_id: str = typer.Argument(..., help="스캔 ID (anshim report list 로 확인)"),
    vuln_id: int | None = typer.Option(
        None, "--vuln", "-v", help="설명을 생성할 취약점 ID. 생략하면 목록만 출력"
    ),
    model: str | None = typer.Option(None, "--model", "-m", help="사용할 Ollama 모델"),
    timeout: int = typer.Option(180, "--timeout", help="LLM 요청 타임아웃 (초)"),
    save: bool = typer.Option(True, "--save/--no-save", help="생성 결과를 DB에 저장"),
) -> None:
    """취약점의 공격 시나리오와 수정 제안을 생성합니다.

    스캔은 탐지와 오탐 판정까지만 수행합니다. 서술 생성은 느리고 비용이 크므로
    이 명령으로 필요한 항목만 따로 생성합니다.
    """
    from anshim.core.analyzers.llm_analyzer import LLMAnalyzer
    from anshim.core.db.repository import ScanRepository, VulnerabilityRepository
    from anshim.core.models import get_recommended_model
    from anshim.core.utils.config_manager import get_config

    scan_repo = ScanRepository()
    scan = scan_repo.get_scan(scan_id)
    if scan is None:
        console.print(f"[red]스캔을 찾을 수 없습니다: {scan_id}[/red]")
        console.print("[dim]anshim report list 로 스캔 ID를 확인하세요.[/dim]")
        raise typer.Exit(1)

    vuln_repo = VulnerabilityRepository()
    vulns = vuln_repo.list_by_scan(scan_id)
    if not vulns:
        console.print("[yellow]이 스캔에는 취약점이 없습니다.[/yellow]")
        raise typer.Exit()

    if vuln_id is None:
        _print_vulnerability_list(vulns)
        console.print(
            f"\n[dim]예: anshim explain {scan_id} --vuln {vulns[0].id}[/dim]",
        )
        raise typer.Exit()

    target = next((v for v in vulns if v.id == vuln_id), None)
    if target is None:
        console.print(f"[red]취약점 #{vuln_id} 은 스캔 {scan_id} 에 없습니다.[/red]")
        raise typer.Exit(1)

    cfg = get_config()
    selected_model = model or cfg.model or get_recommended_model().name

    analyzer = LLMAnalyzer(model=selected_model)
    if not analyzer.is_available():
        console.print("[red]Ollama에 연결할 수 없습니다.[/red]")
        console.print("[dim]ollama serve 로 실행한 뒤 다시 시도하세요.[/dim]")
        raise typer.Exit(1)

    console.print(f"[dim]모델: {selected_model} — 생성에 수십 초가 걸릴 수 있습니다.[/dim]")
    with console.status("공격 시나리오와 수정 제안 생성 중..."):
        explanation = analyzer.explain_vulnerability(_to_analysis_result(target), timeout=timeout)

    _render_explanation(target, explanation)

    metrics = analyzer.metrics.as_dict()
    console.print(
        f"[dim]LLM 호출 {metrics['call_count']}회, "
        f"평균 {metrics['average_seconds']}초, "
        f"JSON 파싱 실패 {metrics['parse_failures']}건[/dim]"
    )

    if save and (explanation.get("attack_scenario") or explanation.get("remediation")):
        vuln_repo.update_explanation(
            vuln_id=target.id,
            attack_scenario=explanation.get("attack_scenario"),
            remediation=explanation.get("remediation"),
        )
        console.print("[green]생성 결과를 저장했습니다.[/green]")
