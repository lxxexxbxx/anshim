"""벤치마크 정답지(labels.yaml)를 코퍼스의 마커에서 생성합니다.

정답지를 손으로 관리하면 코퍼스 파일을 수정할 때마다 라인 번호가 어긋난다.
대신 취약한 코드 바로 위에 마커 주석을 두고, 이 스크립트가 정답지를 만든다.

마커 형식 (취약한 코드 바로 윗줄에 배치):

    # VULN: isms_p=2.10.1 cwe=CWE-89 severity=high
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")

사용법:

    python scripts/generate_labels.py            # benchmarks/labels.yaml 갱신
    python scripts/generate_labels.py --check    # 갱신 필요 여부만 확인 (CI용)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = REPO_ROOT / "benchmarks" / "corpus"
LABELS_PATH = REPO_ROOT / "benchmarks" / "labels.yaml"

_MARKER = re.compile(r"^\s*#\s*VULN:\s*(?P<fields>.+?)\s*$")
_FIELD = re.compile(r"(?P<key>\w+)=(?P<value>\S+)")

# 마커에 반드시 있어야 하는 필드
_REQUIRED_FIELDS = ("isms_p", "cwe", "severity")
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


def _parse_markers(path: Path) -> list[dict]:
    """파일에서 VULN 마커를 찾아 정답 항목 목록을 만듭니다.

    Args:
        path: 코퍼스 파일 경로.

    Returns:
        정답 항목 목록. 각 항목은 line 과 마커 필드를 담는다.

    Raises:
        ValueError: 마커 형식이 잘못되었거나 파일 끝에 마커만 있는 경우.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    expected: list[dict] = []

    for index, line in enumerate(lines):
        match = _MARKER.match(line)
        if not match:
            continue

        fields = {m.group("key"): m.group("value") for m in _FIELD.finditer(match.group("fields"))}

        missing = [f for f in _REQUIRED_FIELDS if f not in fields]
        if missing:
            raise ValueError(f"{path.name}:{index + 1} 마커에 누락된 필드: {', '.join(missing)}")

        if fields["severity"] not in _VALID_SEVERITIES:
            raise ValueError(f"{path.name}:{index + 1} 알 수 없는 severity: {fields['severity']}")

        # 마커는 취약한 코드 바로 윗줄에 있다. 정답 라인은 다음 줄(1-based).
        target_line = index + 2
        if target_line > len(lines):
            raise ValueError(f"{path.name}:{index + 1} 마커 다음 줄이 없다")

        expected.append(
            {
                "line": target_line,
                "isms_p": fields["isms_p"],
                "cwe": fields["cwe"],
                "severity": fields["severity"],
            }
        )

    return expected


def _first_docstring_note(path: Path) -> str:
    """파일 docstring에서 '예상:' 으로 시작하는 설명을 뽑아냅니다.

    Args:
        path: 코퍼스 파일 경로.

    Returns:
        설명 문자열. 없으면 빈 문자열.
    """
    text = path.read_text(encoding="utf-8")
    match = re.search(r"^\s*예상:\s*(?P<note>.+?)(?:\n\s*\n|\n\"\"\")", text, re.DOTALL | re.M)
    if not match:
        return ""
    return " ".join(match.group("note").split())


def build_labels() -> dict:
    """코퍼스 전체를 훑어 정답지 구조를 만듭니다.

    Returns:
        labels.yaml 로 직렬화할 딕셔너리.
    """
    files: list[dict] = []

    for label in ("positive", "negative"):
        directory = CORPUS_DIR / label
        for path in sorted(directory.glob("*.py")):
            expected = _parse_markers(path)

            if label == "negative" and expected:
                raise ValueError(f"{path.name}: negative 파일에 VULN 마커가 있다")
            if label == "positive" and not expected:
                raise ValueError(f"{path.name}: positive 파일에 VULN 마커가 없다")

            entry: dict = {
                "path": f"{label}/{path.name}",
                "label": label,
                "expected": expected,
            }
            note = _first_docstring_note(path)
            if note:
                entry["note"] = note
            files.append(entry)

    positive_count = sum(1 for f in files if f["label"] == "positive")
    negative_count = sum(1 for f in files if f["label"] == "negative")
    total_expected = sum(len(f["expected"]) for f in files)

    return {
        "version": "1.0",
        "description": "AnShim 벤치마크 정답지. scripts/generate_labels.py 가 생성한다. 직접 수정하지 말 것.",
        "summary": {
            "positive_files": positive_count,
            "negative_files": negative_count,
            "expected_findings": total_expected,
        },
        "files": files,
    }


def main() -> int:
    """진입점.

    Returns:
        종료 코드. --check 에서 갱신이 필요하면 1.
    """
    parser = argparse.ArgumentParser(description="벤치마크 정답지 생성")
    parser.add_argument(
        "--check",
        action="store_true",
        help="파일을 쓰지 않고 갱신이 필요한지만 확인한다",
    )
    args = parser.parse_args()

    labels = build_labels()
    rendered = yaml.safe_dump(labels, allow_unicode=True, sort_keys=False, width=100)

    if args.check:
        if not LABELS_PATH.exists() or LABELS_PATH.read_text(encoding="utf-8") != rendered:
            print("labels.yaml 이 코퍼스와 어긋나 있다. scripts/generate_labels.py 를 실행할 것.")
            return 1
        print("labels.yaml 최신 상태")
        return 0

    LABELS_PATH.parent.mkdir(parents=True, exist_ok=True)
    LABELS_PATH.write_text(rendered, encoding="utf-8")
    summary = labels["summary"]
    print(
        f"{LABELS_PATH.relative_to(REPO_ROOT)} 생성: "
        f"positive {summary['positive_files']}개, "
        f"negative {summary['negative_files']}개, "
        f"정답 {summary['expected_findings']}건"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
