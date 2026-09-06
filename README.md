# AnShim (안심)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-153%20passed-brightgreen.svg)]()

> 소스코드를 외부로 반출하지 않는 환경에서 동작하는 SAST 도구.
> 정적 분석 결과를 ISMS-P 인증 항목에 매핑하고 한국어 리포트를 생성한다.

---

## 무엇을 하는 도구인가

Semgrep은 `python.flask.security.injection.sql-injection`을 찾아준다.
하지만 ISMS-P 인증 심사에서 필요한 언어는 **"2.10.1 항목 결함"** 이다.

AnShim은 그 사이를 번역한다. 그리고 두 가지 제약 위에서 동작한다.

**제약 1 — 소스코드를 외부로 보낼 수 없다.**
ISMS-P를 준비하는 금융·공공은 대부분 망분리 환경이다. 코드를 외부 API로 전송하는
도구는 보안 검토 단계에서 탈락한다. 성능이 좋아도 반입 자체가 안 된다.
그래서 LLM은 로컬(Ollama)에서만 동작하고, **없어도 도구는 완전히 동작한다.**

**제약 2 — 오탐이 많으면 아무도 안 쓴다.**
Bandit B303은 MD5를 용도와 무관하게 잡는다. 파일 체크섬용 MD5까지 취약점으로
올라오면 실무자는 결과 전체를 무시하게 된다.

---

## 핵심: 측정된 도구

이 프로젝트의 차별점은 기능이 아니라 **검증**이다.

"LLM이 오탐을 줄인다"는 주장을 검증하기 위해, **규칙 기반이 오탐하기 쉬운 정상 코드**를
의도적으로 설계한 벤치마크 코퍼스를 만들었다.

| negative 케이스 | 왜 어려운가 |
|---|---|
| MD5를 파일 체크섬으로 사용 | Bandit은 용도를 구분하지 못한다 |
| 테스트 픽스처의 더미 API 키 | 하드코딩 시크릿 룰이 잡지만 실제 위험이 아니다 |
| 테이블명만 포매팅, 값은 파라미터화 | 포맷 문자열 + execute 패턴으로 보인다 |
| `os.getenv("KEY", "dev-default")` | 기본값 문자열이 시크릿으로 오탐된다 |

취약한 코드만으로는 Precision이 항상 100%로 나와 오탐을 측정할 수 없다.

### 측정 결과

코퍼스 16파일(positive 8 / negative 8), 정답 15건. RTX 4060 Laptop 8GB / RAM 31GB.

LLM은 오탐을 결과에서 삭제하지 않고 표시만 한다. 아래 유효 지표는 사용자가
그 표시를 신뢰한다고 가정했을 때 실제로 마주하는 값이다.

| 구성 | 유효 Precision | 유효 Recall | 유효 F1 | 남은 오탐 | 스캔 시간 | JSON 파싱 실패율 |
|---|---|---|---|---|---|---|
| 규칙 기반만 | 0.600 | 0.800 | 0.686 | 8 | 10.3초 | - |
| + 2.4B | 0.600 | 0.800 | 0.686 | 8 | 30.6초 | 0.0% |
| + 7.8B | **1.000** | 0.800 | **0.889** | **0** | 61.9초 | 0.0% |

7.8B 구성은 negative 코퍼스의 오탐 8건을 전부 표시했고, 진짜 취약점은 하나도
오탐으로 표시하지 않았다. Recall 은 세 구성 모두 0.800 으로 동일하다.

### 여기까지 오는 데 필요했던 것

처음 측정에서는 LLM 레이어가 오탐을 한 건도 걸러내지 못했다. 원인을 나눠 보니
세 가지가 동시에 필요했다.

| 조건 | 없을 때 |
|---|---|
| 폐쇄형 분류 프롬프트 | 긴 서술을 JSON 에 담느라 파싱 실패 42.5% |
| 충분한 코드 컨텍스트 | 분석기가 주는 3줄로는 용도 판별이 불가능 |
| 7.8B 이상 모델 | 2.4B 는 탐지기 판정을 그대로 복창 |

가장 큰 병목은 컨텍스트였다. Bandit 은 3줄, Semgrep 무료 티어는 `requires login`
플레이스홀더를 코드로 넘긴다. 함수 이름과 docstring 이 보이지 않으면 같은
`hashlib.md5()` 호출이 체크섬인지 비밀번호 해싱인지 구분할 방법이 없다.
파일에서 직접 컨텍스트를 구성하도록 바꾼 뒤에야 두 경우가 갈렸다.

개선 전후 (7.8B 기준):

| | 스캔 시간 | LLM 호출 | JSON 파싱 실패율 | 유효 F1 |
|---|---|---|---|---|
| 개선 전 | 763.0초 | 94 | 42.5% | 0.686 |
| 개선 후 | 61.9초 | 32 | 0.0% | 0.889 |

취약점 1건당 3회 호출하던 것을 1회로 줄였다. 공격 시나리오와 수정 제안은
스캔에서 분리해 `anshim explain` 으로 옮겼다.

측정 결과 원본은 [`benchmarks/results/`](benchmarks/results/) 에 JSON 으로 커밋되어 있다.
실행 시각, 모델 태그, 커밋 해시, 하드웨어가 함께 기록되어 재현할 수 있다.
정답지는 [`benchmarks/labels.yaml`](benchmarks/labels.yaml) 이며 코퍼스의 마커에서 생성된다.

### 이 측정의 한계

- 코퍼스가 16파일로 작다. 통계적 유의성을 주장하지 않는다.
- 코퍼스를 직접 설계했으므로 선택 편향이 있다. 표준 벤치마크(OWASP Benchmark,
  Juliet Test Suite) 적용은 향후 과제다.
- Python 단일 언어 기준이며 다른 언어로 일반화할 수 없다.
- 단일 하드웨어에서 1회 측정이다. 반복 측정의 분산은 확인하지 않았다.

### 그래서 기본값을 이렇게 정했다

**기본은 규칙 기반이고 LLM 은 옵트인이다.** `--llm` 또는 `--model` 로 켠다.
근거는 위 측정이다.

- Ollama 없이도 동작해야 한다. 컴플라이언스 매핑은 결정론적이므로 LLM 이 필요 없다.
- 2.4B 에서는 효과가 없었다. 소형 모델을 쓰는 저사양 환경에서 켜면 시간만 든다.
- 10초 스캔은 CI 에 넣을 수 있지만 62초는 어렵다.

7.8B 미만 모델로 LLM 을 켜면 벤치마크에서 효과가 없었다는 경고를 출력한다.

---

## 빠른 시작

```bash
git clone https://github.com/lxxexxbxx/anshim.git
cd anshim
pip install -e .

# 기본 실행 (규칙 기반, Ollama 불필요)
anshim scan benchmarks/corpus/positive --open
```

로컬 LLM 문맥 분류를 추가하려면 (7.8B 이상 권장):

```bash
anshim init                    # 하드웨어 감지 → 모델 추천 → config 생성
anshim scan benchmarks/corpus/positive --model exaone3.5:7.8b --open
```

출력 예시:

```
[AnShim] 분석 완료: 7건 발견
  [CRITICAL] 2.7.2  하드코딩된 시크릿 키 - app.py:13
  [CRITICAL] 2.11.1 MD5 비밀번호 해시 - app.py:65
  [CRITICAL] 3.3.1  주민번호 평문 저장 - app.py:72
  [HIGH]     2.10.1 SQL 인젝션 - app.py:115
  [HIGH]     2.10.2 XSS (Stored) - app.py:130
  [HIGH]     2.10.3 CSRF 미적용 - app.py:103
  [MEDIUM]   2.9.1  디버그 모드 활성화 - app.py:20
```

---

## 아키텍처

```
Semgrep / Bandit  →  탐지 + 심각도          결정론적
        ↓
LLM (선택)        →  문맥 분류               없어도 동작
        ↓
매핑 엔진         →  ISMS-P 항목 확정        결정론적
        ↓
리포트            →  HTML / Excel / JSON / SARIF 2.1.0
```

**LLM은 최종 판단을 하지 않는다.** 탐지와 심각도는 전부 규칙 기반이 결정하고,
LLM에는 결정론적으로 판정하기 어려운 문맥 분류만 넘긴다.
Ollama가 없으면 자동으로 규칙 기반 경로로 전환된다.


---

## 매핑 구조

취약점 탐지 룰을 새로 만들지 않는다. 외부 도구의 룰 ID를 인증 항목으로 역매핑한다.

```yaml
id: 2.10.1-sql-injection
applicable_to: [isms, isms-p]      # ISMS 스캔 시 3.x 룰 자동 제외
severity: critical
semgrep_rule_ids:
  - "python.flask.security.injection.sql-injection"
  - "java.lang.security.audit.sqli.jdbc-sqli"
bandit_test_ids: ["B608", "B610", "B611"]
cwe_ids: ["CWE-89"]
owasp_ids: ["A03:2021"]
```

N개의 외부 룰이 1개의 인증 항목으로 묶이므로, 외부 도구가 룰을 추가해도
매핑 YAML만 갱신하면 된다.

---

## 커버리지 — 무엇을 할 수 없는가

**ISMS-P 101개 항목 중 코드로 검증 가능한 것은 30% 미만이다.**

| 등급 | 항목 수 | 의미 |
|---|---|---|
| A. 자동 검증 | 약 15개 | 코드만으로 결함 판정 가능 |
| B. 부분 검증 | 약 18개 | 단서는 얻지만 추가 확인 필요 |
| C. 검증 불가 | 약 68개 | 정책, 조직, 물리 보안, 인터뷰 영역 |

**이 도구만으로 인증 대응이 되지 않는다.** 자동화 도구의 가장 위험한 사용법은
"스캔을 통과했으니 준비가 됐다"고 판단하는 것이다.


---

## CLI

```bash
anshim init                                   # 하드웨어 감지, 모델 추천
anshim scan <path>                            # 스캔
anshim explain <scan-id> --vuln <n>           # 공격 시나리오/수정 제안 생성
anshim serve                                  # 웹 대시보드 (localhost:3000)
anshim models list | pull <tag> | recommend
anshim report list | show <id> | export <id>
```

주요 scan 옵션:

```
--llm                  LLM 문맥 분류 활성화 (기본: 비활성)
--model <tag>          Ollama 모델 지정 (지정하면 LLM 자동 활성화)
--rule-only            규칙 기반만 (기본 동작과 동일, 호환용)
--compliance <types>   isms | isms-p | owasp | cwe (복수는 쉼표)
--severity <level>     심각도 필터
--excel                Excel 리포트 추가 생성
--open                 완료 후 브라우저 오픈
```

---

## 구현 현황

| 항목 | 내용 |
|---|---|
| 코드 규모 | 약 9,000 라인 (Python + Next.js) |
| 테스트 | pytest 153건 |
| 매핑 룰셋 | ISMS-P 10 / OWASP 5 / CWE 3 |
| 리포트 | HTML, Excel, JSON, SARIF 2.1.0 |
| 지원 언어 | Python (Bandit + Semgrep), JS/TS, Java (Semgrep) |

### 기술 스택

```
Python 3.10+   Typer CLI, Pydantic 모델 정규화
SQLAlchemy     ORM, SQLite
FastAPI        REST API
Next.js 14     웹 대시보드 (App Router, TypeScript)
Ollama         로컬 LLM 런타임 (EXAONE 3.5 / Qwen)
Semgrep        정적 분석 엔진
Bandit         Python 보안 분석
Jinja2         HTML 리포트 + LLM 프롬프트 템플릿
pytest, ruff, mypy
```

---

## 한계

과장하지 않기 위해 명시한다.

- **실사용 검증 없음.** 실제 기업 코드베이스에서 돌려보지 않았다.
  프레임워크 관용구나 사내 래퍼로 인한 오탐이 훨씬 많을 것으로 예상한다.
- **벤치마크 코퍼스가 자체 제작.** 규모가 작고 선택 편향이 있다.
  표준 벤치마크(OWASP Benchmark, Juliet) 적용은 향후 과제.
- **커버리지 30%.** 위 커버리지 절 참조.
- **프롬프트 인젝션 방어 불완전.** 구분자 격리 수준이며, LLM 출력이 최종 판정을
  결정하지 않는 구조로 영향을 제한했을 뿐이다.


---

## 개발

```bash
pip install -e ".[dev]"

pytest tests/
ruff check --fix .
ruff format .
mypy .

# 벤치마크 재현
python scripts/benchmark.py --all
python scripts/benchmark.py --report
```


---

## 저장소 구성

| 경로 | 내용 |
|---|---|
| [`src/anshim/`](src/anshim/) | 파이썬 패키지 (CLI, 분석기, 컴플라이언스 매퍼, 리포터) |
| [`src/anshim/rules/`](src/anshim/rules/) | ISMS-P / OWASP / CWE 룰셋 YAML |
| [`benchmarks/corpus/`](benchmarks/corpus/) | 벤치마크 코퍼스 (positive 8, negative 8) |
| [`benchmarks/labels.yaml`](benchmarks/labels.yaml) | 정답지 (코퍼스 마커에서 생성) |
| [`benchmarks/results/`](benchmarks/results/) | 측정 결과 JSON |
| [`scripts/benchmark.py`](scripts/benchmark.py) | 벤치마크 러너 |
| [`tests/`](tests/) | pytest |

---

## 라이선스

MIT
