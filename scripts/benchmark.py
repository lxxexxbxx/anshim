"""AnShim 벤치마크 러너.

`benchmarks/corpus/` 의 코퍼스를 `benchmarks/labels.yaml` 의 정답지와 대조해서
구성별 정확도와 운영 지표를 측정한다. 설계 명세는 저장소 외부 문서로 관리한다.

중요: 분석은 반드시 기존 `HybridAnalyzer` 를 그대로 호출한다. 벤치마크 전용
분석 경로를 만들면 "벤치마크에서만 잘 나오는" 결과가 되고, 그건 측정이 아니다.

사용법:

    python scripts/benchmark.py --config rule-only
    python scripts/benchmark.py --config llm --model exaone3.5:7.8b
    python scripts/benchmark.py --all
    python scripts/benchmark.py --report
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from anshim.core.analyzers.hybrid import HybridAnalyzer  # noqa: E402
from anshim.core.utils.hardware import detect_hardware  # noqa: E402

BENCHMARK_DIR = REPO_ROOT / "benchmarks"
CORPUS_DIR = BENCHMARK_DIR / "corpus"
LABELS_PATH = BENCHMARK_DIR / "labels.yaml"
RESULTS_DIR = BENCHMARK_DIR / "results"

# 탐지 라인과 정답 라인의 허용 오차. 도구마다 리포트하는 라인이 다르다.
LINE_TOLERANCE = 2

logger = logging.getLogger("benchmark")


@dataclass
class Counts:
    """혼동 행렬 집계.

    Attributes:
        tp: 정답에 있는 취약점을 탐지한 건수.
        fp: negative 파일에서 탐지한 건수(오탐).
        fn: positive 파일에서 놓친 건수(미탐).
        tn: negative 파일 중 아무것도 탐지되지 않은 파일 수.
    """

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        """탐지한 것 중 진짜 비율."""
        denominator = self.tp + self.fp
        return self.tp / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        """찾아야 할 것 중 찾은 비율."""
        denominator = self.tp + self.fn
        return self.tp / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        """Precision과 Recall의 조화평균."""
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def as_dict(self) -> dict[str, float | int]:
        """직렬화 가능한 형태로 변환합니다."""
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


@dataclass
class FileOutcome:
    """파일 1건의 판정 결과.

    Attributes:
        path: 코퍼스 상대 경로.
        label: positive 또는 negative.
        matched: 정답과 매칭된 탐지 목록.
        missed: 탐지되지 않은 정답 목록.
        spurious: 정답에 없는데 탐지된 목록.
        flagged_false_positive: LLM이 오탐으로 표시한 건수.
    """

    path: str
    label: str
    matched: list[dict] = field(default_factory=list)
    missed: list[dict] = field(default_factory=list)
    spurious: list[dict] = field(default_factory=list)
    flagged_false_positive: int = 0

    def as_dict(self) -> dict[str, Any]:
        """직렬화 가능한 형태로 변환합니다."""
        return {
            "path": self.path,
            "label": self.label,
            "matched": self.matched,
            "missed": self.missed,
            "spurious": self.spurious,
            "flagged_false_positive": self.flagged_false_positive,
        }


def _git_commit() -> str:
    """현재 커밋 해시를 반환합니다.

    Returns:
        짧은 커밋 해시. 확인할 수 없으면 "unknown".
    """
    try:
        out = subprocess.run(  # noqa: S603
            ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return out.stdout.strip() or "unknown"


def _peak_memory_mb() -> float | None:
    """현재 프로세스의 최대 메모리 사용량(MB)을 반환합니다.

    Returns:
        최대 RSS(MB). 측정할 수 없으면 None.
    """
    try:
        import psutil
    except ImportError:
        return None
    try:
        info = psutil.Process().memory_info()
    except Exception:
        return None
    # peak_wset은 Windows 전용이다. 없으면 현재 RSS로 대체한다.
    peak = getattr(info, "peak_wset", None) or info.rss
    return round(peak / (1024 * 1024), 1)


def load_labels() -> dict:
    """정답지를 로드합니다.

    Returns:
        labels.yaml 내용.

    Raises:
        FileNotFoundError: 정답지가 없는 경우.
    """
    if not LABELS_PATH.exists():
        raise FileNotFoundError(
            f"정답지가 없습니다: {LABELS_PATH}\n"
            "먼저 `python scripts/generate_labels.py` 를 실행하세요."
        )
    return yaml.safe_load(LABELS_PATH.read_text(encoding="utf-8"))


def _detections_for_file(result: Any, corpus_path: Path) -> list[dict]:
    """스캔 결과에서 특정 파일의 탐지 목록을 추출합니다.

    Args:
        result: HybridScanResult.
        corpus_path: 대상 파일의 절대 경로.

    Returns:
        탐지 목록. 각 항목은 line, rule_id, severity, is_false_positive를 담는다.
    """
    target = corpus_path.resolve()
    detections: list[dict] = []
    for item in result.results:
        try:
            same_file = Path(item.file_path).resolve() == target
        except OSError:
            same_file = False
        if not same_file:
            continue
        detections.append(
            {
                "line": item.line_start,
                "rule_id": item.rule_id,
                "severity": item.severity,
                "source": item.source,
                "is_false_positive": bool(getattr(item, "is_false_positive", False)),
            }
        )
    return detections


def _evaluate_file(entry: dict, detections: list[dict]) -> FileOutcome:
    """파일 1건의 탐지 결과를 정답과 대조합니다.

    정답 1건은 탐지 1건에만 매칭된다(중복 매칭 금지). 같은 라인에 여러 룰이
    탐지되면 첫 건만 TP가 되고 나머지는 spurious로 분류한다.

    Args:
        entry: labels.yaml 의 파일 항목.
        detections: 해당 파일의 탐지 목록.

    Returns:
        판정 결과.
    """
    outcome = FileOutcome(path=entry["path"], label=entry["label"])
    outcome.flagged_false_positive = sum(1 for d in detections if d["is_false_positive"])

    expected = list(entry.get("expected") or [])
    unmatched_detections = list(detections)

    for exp in expected:
        hit = None
        for det in unmatched_detections:
            if abs(det["line"] - exp["line"]) <= LINE_TOLERANCE:
                hit = det
                break
        if hit is None:
            outcome.missed.append(exp)
        else:
            unmatched_detections.remove(hit)
            outcome.matched.append({"expected": exp, "detected": hit})

    outcome.spurious = unmatched_detections
    return outcome


def run_config(
    name: str,
    model: str | None,
    skip_llm: bool,
    compliance: list[str],
    llm_timeout: int,
) -> dict:
    """한 가지 구성으로 벤치마크를 실행합니다.

    Args:
        name: 구성 이름 (결과 파일명에 쓰인다).
        model: 사용할 Ollama 모델 태그. skip_llm이면 무시된다.
        skip_llm: LLM 분석을 건너뛸지 여부.
        compliance: 적용할 컴플라이언스 유형.
        llm_timeout: LLM 요청 타임아웃(초).

    Returns:
        측정 결과 딕셔너리.
    """
    labels = load_labels()
    analyzer = HybridAnalyzer(model=model, compliance_types=compliance)

    if not skip_llm and not analyzer.llm_available:
        logger.warning(
            "Ollama에 연결할 수 없습니다. 구성 '%s'는 LLM 없이 실행됩니다. "
            "결과에 llm_requested=True, llm_actually_ran=False로 기록합니다.",
            name,
        )

    llm_actually_ran = not skip_llm and analyzer.llm_available

    logger.info("구성 '%s' 실행: 코퍼스 전체를 한 번에 스캔합니다.", name)
    started = time.perf_counter()
    scan = analyzer.analyze(
        target=CORPUS_DIR,
        skip_llm=skip_llm,
        llm_timeout=llm_timeout,
    )
    elapsed = time.perf_counter() - started

    counts = Counts()
    outcomes: list[FileOutcome] = []

    for entry in labels["files"]:
        corpus_path = CORPUS_DIR / entry["path"]
        detections = _detections_for_file(scan, corpus_path)
        outcome = _evaluate_file(entry, detections)
        outcomes.append(outcome)

        counts.tp += len(outcome.matched)
        counts.fn += len(outcome.missed)
        if entry["label"] == "negative":
            counts.fp += len(outcome.spurious)
            if not outcome.spurious:
                counts.tn += 1
        else:
            # positive 파일의 초과 탐지는 같은 취약점에 대한 중복 룰인 경우가 많다.
            # FP로 세지 않되 결과에는 남겨 사후 분석이 가능하게 한다.
            pass

    hardware = detect_hardware()

    return {
        "config": name,
        "model": model if llm_actually_ran else None,
        "llm_requested": not skip_llm,
        "llm_actually_ran": llm_actually_ran,
        "compliance": compliance,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "commit": _git_commit(),
        "line_tolerance": LINE_TOLERANCE,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "ram_gb": round(hardware.ram_gb, 1),
            "gpu": hardware.gpu_name,
            "vram_gb": round(hardware.gpu_vram_gb, 1) if hardware.gpu_vram_gb else None,
        },
        "corpus": labels["summary"],
        "accuracy": counts.as_dict(),
        "operational": {
            "total_seconds": round(elapsed, 2),
            "scanned_files": scan.scanned_files,
            "total_detections": len(scan.results),
            "false_positives_removed": scan.false_positives_removed,
            "peak_memory_mb": _peak_memory_mb(),
            "llm": analyzer.llm_metrics,
        },
        "files": [o.as_dict() for o in outcomes],
    }


def save_result(result: dict) -> Path:
    """측정 결과를 JSON으로 저장합니다.

    Args:
        result: run_config가 반환한 결과.

    Returns:
        저장한 파일 경로.
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = RESULTS_DIR / f"{result['config']}_{stamp}.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _latest_results() -> list[dict]:
    """구성별로 가장 최근 결과를 하나씩 모읍니다.

    Returns:
        결과 목록. 파일이 없으면 빈 목록.
    """
    if not RESULTS_DIR.exists():
        return []
    by_config: dict[str, tuple[float, dict]] = {}
    for path in RESULTS_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("결과 파일을 읽을 수 없습니다: %s", path.name)
            continue
        config = data.get("config", path.stem)
        mtime = path.stat().st_mtime
        if config not in by_config or mtime > by_config[config][0]:
            by_config[config] = (mtime, data)
    return [data for _, data in sorted(by_config.values(), key=lambda x: x[1].get("config", ""))]


def render_report() -> str:
    """results/ 의 최신 결과를 마크다운 표로 변환합니다.

    Returns:
        마크다운 문자열.
    """
    results = _latest_results()
    if not results:
        return "측정 결과가 없습니다. 먼저 `python scripts/benchmark.py --all` 을 실행하세요.\n"

    lines: list[str] = ["## 정확도", ""]
    lines.append("| 구성 | TP | FP | FN | TN | Precision | Recall | F1 |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for r in results:
        a = r["accuracy"]
        lines.append(
            f"| {r['config']} | {a['tp']} | {a['fp']} | {a['fn']} | {a['tn']} | "
            f"{a['precision']:.3f} | {a['recall']:.3f} | {a['f1']:.3f} |"
        )

    lines += ["", "## 운영 지표", ""]
    lines.append("| 구성 | 스캔 시간 | LLM 호출 | 평균 응답 | JSON 실패율 | 최대 메모리 |")
    lines.append("|---|---|---|---|---|---|")
    for r in results:
        op = r["operational"]
        llm = op.get("llm")
        if llm:
            calls = str(llm["call_count"])
            avg = f"{llm['average_seconds']:.2f}s"
            fail = f"{llm['parse_failure_rate'] * 100:.1f}%"
        else:
            calls, avg, fail = "0", "—", "—"
        memory = f"{op['peak_memory_mb']}MB" if op.get("peak_memory_mb") else "—"
        lines.append(
            f"| {r['config']} | {op['total_seconds']:.1f}s | {calls} | {avg} | {fail} | {memory} |"
        )

    lines += ["", "## negative 케이스별 오탐 여부", ""]
    negative_paths = sorted(
        {f["path"] for r in results for f in r["files"] if f["label"] == "negative"}
    )
    header = "| negative 케이스 | " + " | ".join(r["config"] for r in results) + " |"
    lines.append(header)
    lines.append("|---" * (len(results) + 1) + "|")
    for path in negative_paths:
        cells = []
        for r in results:
            entry = next((f for f in r["files"] if f["path"] == path), None)
            if entry is None:
                cells.append("—")
            elif entry["spurious"]:
                cells.append(f"오탐 {len(entry['spurious'])}건")
            else:
                cells.append("정상")
        name = path.split("/", 1)[-1]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")

    lines.append("")
    return "\n".join(lines)


CONFIGS: dict[str, dict] = {
    "rule-only": {"model": None, "skip_llm": True},
    "llm": {"model": None, "skip_llm": False},
}


def main() -> int:
    """진입점.

    Returns:
        종료 코드.
    """
    parser = argparse.ArgumentParser(description="AnShim 벤치마크 러너")
    parser.add_argument("--config", choices=sorted(CONFIGS), help="실행할 구성")
    parser.add_argument("--model", help="Ollama 모델 태그 (--config llm 에서 사용)")
    parser.add_argument("--name", help="결과 파일에 쓸 구성 이름 (기본: config 또는 모델 태그)")
    parser.add_argument("--all", action="store_true", help="rule-only 와 지정 모델들을 순차 실행")
    parser.add_argument("--models", nargs="*", default=[], help="--all 에서 측정할 모델 태그 목록")
    parser.add_argument("--report", action="store_true", help="results/ 를 마크다운 표로 출력")
    parser.add_argument("--compliance", default="isms-p", help="컴플라이언스 유형 (쉼표 구분)")
    parser.add_argument("--llm-timeout", type=int, default=90, help="LLM 요청 타임아웃(초)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.report:
        print(render_report())
        return 0

    if not args.config and not args.all:
        parser.error("--config, --all, --report 중 하나를 지정하세요")

    compliance = [c.strip() for c in args.compliance.split(",") if c.strip()]
    plan: list[tuple[str, str | None, bool]] = []

    if args.all:
        plan.append(("rule-only", None, True))
        for model in args.models:
            plan.append((model.replace(":", "-"), model, False))
        if not args.models:
            logger.warning("--models 가 비어 있어 규칙 기반 구성만 측정합니다.")
    else:
        skip_llm = CONFIGS[args.config]["skip_llm"]
        model = args.model if not skip_llm else None
        if not skip_llm and not model:
            parser.error("--config llm 에는 --model 이 필요합니다")
        default_name = args.config if skip_llm else str(model).replace(":", "-")
        plan.append((args.name or default_name, model, skip_llm))

    for name, model, skip_llm in plan:
        result = run_config(name, model, skip_llm, compliance, args.llm_timeout)
        path = save_result(result)
        acc = result["accuracy"]
        logger.info(
            "[%s] TP=%d FP=%d FN=%d | P=%.3f R=%.3f F1=%.3f | %.1fs -> %s",
            name,
            acc["tp"],
            acc["fp"],
            acc["fn"],
            acc["precision"],
            acc["recall"],
            acc["f1"],
            result["operational"]["total_seconds"],
            path.name,
        )

    print()
    print(render_report())
    return 0


if __name__ == "__main__":
    sys.exit(main())
