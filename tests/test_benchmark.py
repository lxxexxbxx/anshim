"""벤치마크 러너와 정답지 생성기 테스트.

측정 도구 자체가 틀리면 측정 결과 전체가 무의미하므로, 매칭 규칙과
지표 계산을 직접 검증한다.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_script(name: str) -> ModuleType:
    """scripts/ 아래 스크립트를 모듈로 로드합니다.

    scripts/ 는 패키지가 아니므로 일반 import로는 불러올 수 없다.

    Args:
        name: 확장자를 뺀 스크립트 이름.

    Returns:
        로드된 모듈.
    """
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_script_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


benchmark = _load_script("benchmark")
generate_labels = _load_script("generate_labels")


class TestCounts:
    """지표 계산 검증."""

    def test_기본값은_0으로_나누지_않는다(self) -> None:
        counts = benchmark.Counts()
        assert counts.precision == 0.0
        assert counts.recall == 0.0
        assert counts.f1 == 0.0

    def test_지표_계산(self) -> None:
        counts = benchmark.Counts(tp=12, fp=8, fn=3, tn=4)
        assert counts.precision == pytest.approx(12 / 20)
        assert counts.recall == pytest.approx(12 / 15)
        assert counts.f1 == pytest.approx(2 * 0.6 * 0.8 / (0.6 + 0.8))

    def test_완벽한_탐지(self) -> None:
        counts = benchmark.Counts(tp=10, fp=0, fn=0, tn=5)
        assert counts.precision == 1.0
        assert counts.recall == 1.0
        assert counts.f1 == 1.0


class TestEvaluateFile:
    """정답 매칭 규칙 검증."""

    def _entry(self, label: str, expected: list[dict]) -> dict:
        return {"path": f"{label}/sample.py", "label": label, "expected": expected}

    def _detection(self, line: int, rule_id: str = "r1", is_fp: bool = False) -> dict:
        return {
            "line": line,
            "rule_id": rule_id,
            "severity": "high",
            "source": "bandit",
            "is_false_positive": is_fp,
        }

    def test_정확히_같은_라인은_매칭된다(self) -> None:
        entry = self._entry("positive", [{"line": 10, "cwe": "CWE-89", "severity": "high"}])
        outcome = benchmark._evaluate_file(entry, [self._detection(10)])
        assert len(outcome.matched) == 1
        assert outcome.missed == []
        assert outcome.spurious == []

    def test_허용_오차_내의_라인은_매칭된다(self) -> None:
        """도구마다 리포트하는 라인이 달라 오차를 허용한다."""
        entry = self._entry("positive", [{"line": 10, "cwe": "CWE-89", "severity": "high"}])
        for line in (8, 9, 11, 12):
            outcome = benchmark._evaluate_file(entry, [self._detection(line)])
            assert len(outcome.matched) == 1, f"line={line} 이 매칭되지 않았다"

    def test_허용_오차를_넘으면_미탐이자_초과탐지다(self) -> None:
        entry = self._entry("positive", [{"line": 10, "cwe": "CWE-89", "severity": "high"}])
        outcome = benchmark._evaluate_file(entry, [self._detection(13)])
        assert outcome.matched == []
        assert len(outcome.missed) == 1
        assert len(outcome.spurious) == 1

    def test_정답_하나에_탐지_하나만_매칭된다(self) -> None:
        """같은 라인에 여러 룰이 걸려도 정답 1건은 1건만 소비한다."""
        entry = self._entry("positive", [{"line": 10, "cwe": "CWE-89", "severity": "high"}])
        detections = [self._detection(10, "r1"), self._detection(10, "r2")]
        outcome = benchmark._evaluate_file(entry, detections)
        assert len(outcome.matched) == 1
        assert len(outcome.spurious) == 1

    def test_negative_파일의_모든_탐지는_초과탐지다(self) -> None:
        entry = self._entry("negative", [])
        outcome = benchmark._evaluate_file(entry, [self._detection(5), self._detection(9)])
        assert outcome.matched == []
        assert outcome.missed == []
        assert len(outcome.spurious) == 2

    def test_탐지가_없는_negative_는_깨끗하다(self) -> None:
        entry = self._entry("negative", [])
        outcome = benchmark._evaluate_file(entry, [])
        assert outcome.spurious == []

    def test_LLM이_오탐으로_표시한_건수를_센다(self) -> None:
        entry = self._entry("negative", [])
        detections = [self._detection(5, is_fp=True), self._detection(9, is_fp=False)]
        outcome = benchmark._evaluate_file(entry, detections)
        assert outcome.flagged_false_positive == 1


class TestLabelsInSync:
    """정답지가 코퍼스와 일치하는지 검증."""

    def test_labels_yaml_은_코퍼스와_동기화되어_있다(self) -> None:
        """코퍼스를 수정하고 generate_labels.py 를 안 돌리면 여기서 걸린다."""
        labels = generate_labels.build_labels()
        loaded = benchmark.load_labels()
        assert labels["summary"] == loaded["summary"]
        assert [f["path"] for f in labels["files"]] == [f["path"] for f in loaded["files"]]
        for built, stored in zip(labels["files"], loaded["files"], strict=True):
            assert built["expected"] == stored["expected"], f"{built['path']} 정답이 어긋난다"

    def test_정답_라인은_주석이_아닌_실제_코드를_가리킨다(self) -> None:
        labels = benchmark.load_labels()
        for entry in labels["files"]:
            lines = (benchmark.CORPUS_DIR / entry["path"]).read_text(encoding="utf-8").splitlines()
            for exp in entry["expected"]:
                code = lines[exp["line"] - 1].strip()
                assert code, f"{entry['path']}:{exp['line']} 이 빈 줄이다"
                assert not code.startswith("#"), f"{entry['path']}:{exp['line']} 이 주석이다"

    def test_negative_파일에는_정답이_없다(self) -> None:
        labels = benchmark.load_labels()
        for entry in labels["files"]:
            if entry["label"] == "negative":
                assert entry["expected"] == [], f"{entry['path']} 에 정답이 있다"


class TestLLMMetrics:
    """LLM 계측값 검증."""

    def test_파싱_성공과_실패를_구분해_집계한다(self) -> None:
        from anshim.core.analyzers.llm_analyzer import LLMAnalyzer

        analyzer = LLMAnalyzer(model="dummy")
        assert analyzer._parse_json_response('{"is_false_positive": true}') == {
            "is_false_positive": True
        }
        assert analyzer._parse_json_response('```json\n{"a": 1}\n```') == {"a": 1}
        assert analyzer._parse_json_response("JSON을 만들 수 없습니다") is None
        assert analyzer._parse_json_response("") is None

        metrics = analyzer.metrics
        assert metrics.parse_attempts == 4
        assert metrics.parse_failures == 2
        assert metrics.parse_failure_rate == pytest.approx(0.5)

    def test_호출_시간과_실패를_기록한다(self) -> None:
        from anshim.core.analyzers.llm_analyzer import LLMMetrics

        metrics = LLMMetrics()
        metrics.record_call(1.0)
        metrics.record_call(3.0)
        metrics.record_call(2.0, failed=True)

        assert metrics.call_count == 3
        assert metrics.total_seconds == pytest.approx(6.0)
        assert metrics.average_seconds == pytest.approx(2.0)
        assert metrics.error_count == 1

    def test_호출이_없으면_평균은_0이다(self) -> None:
        from anshim.core.analyzers.llm_analyzer import LLMMetrics

        metrics = LLMMetrics()
        assert metrics.average_seconds == 0.0
        assert metrics.parse_failure_rate == 0.0
        assert metrics.as_dict()["call_count"] == 0


class TestLLMOutputNormalization:
    """LLM 출력 타입 정규화 검증.

    회귀 방지: 모델이 문자열 대신 리스트를 반환하면 MappedResult 검증에서
    스캔 전체가 중단됐다. 벤치마크 실행 중 실제로 발생한 크래시다.
    """

    def test_리스트를_문자열로_정규화한다(self) -> None:
        from anshim.core.analyzers.llm_analyzer import _as_text

        assert _as_text(["2.7.1 암호화 적용", "2.10.1 보안 요구사항 정의"]) == (
            "2.7.1 암호화 적용, 2.10.1 보안 요구사항 정의"
        )
        assert _as_text({"a": "x"}) == "a: x"
        assert _as_text(None) == ""
        assert _as_text("그대로") == "그대로"

    def test_불리언이_아닌_값을_정규화한다(self) -> None:
        from anshim.core.analyzers.llm_analyzer import _as_bool

        assert _as_bool("true") is True
        assert _as_bool("예") is True
        assert _as_bool(1) is True
        assert _as_bool("false") is False
        assert _as_bool(None) is False

    def test_최상위가_배열인_응답은_파싱_실패로_처리한다(self) -> None:
        from anshim.core.analyzers.llm_analyzer import LLMAnalyzer

        analyzer = LLMAnalyzer(model="dummy")
        assert analyzer._parse_json_response("[1, 2, 3]") is None
        assert analyzer.metrics.parse_failures == 1

    def test_LLM이_리스트를_반환해도_컴플라이언스_매핑이_통과한다(self) -> None:
        """실제 크래시를 재현한다. 정규화 전에는 ValidationError 로 죽었다."""
        from anshim.core.analyzers.models import AnalysisResult
        from anshim.core.compliance.mapper import MappedResult

        result = AnalysisResult(
            rule_id="bandit.B324",
            title="취약한 해시 알고리즘",
            description="MD5 사용",
            severity="high",
            file_path="sample.py",
            line_start=10,
            source="bandit",
        )
        data = result.model_dump()
        # 정규화를 거친 값이라면 문자열이어야 한다
        from anshim.core.analyzers.llm_analyzer import _as_text

        data["isms_relevance"] = _as_text(["2.7.1 암호화 적용", "2.10.1 보안 요구사항 정의"])
        data["llm_analysis"] = _as_text(["문장1", "문장2"])

        mapped = MappedResult(**data, compliance_mappings=[])
        assert isinstance(mapped.isms_relevance, str)
        assert "2.7.1" in mapped.isms_relevance
