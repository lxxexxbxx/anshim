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
모델 티어별 측정 결과와 그에 따른 설계 변경은 [`docs/BENCHMARK.md`](docs/BENCHMARK.md) 참조.

---

## 빠른 시작

```bash
git clone https://github.com/lxxexxbxx/anshim.git
cd anshim
pip install -e .

# LLM 없이 즉시 실행
anshim scan docs/demo/demo_target --rule-only --open
```

로컬 LLM을 쓰려면:

```bash
anshim init                    # 하드웨어 감지 → 모델 추천 → config 생성
anshim scan docs/demo/demo_target --compliance isms-p --open
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

상세: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

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

항목별 판정: [`docs/ISMS_P_COVERAGE.md`](docs/ISMS_P_COVERAGE.md)

---

## CLI

```bash
anshim init                                   # 하드웨어 감지, 모델 추천
anshim scan <path>                            # 스캔
anshim serve                                  # 웹 대시보드 (localhost:3000)
anshim models list | pull <tag> | recommend
anshim report list | show <id> | export <id>
```

주요 scan 옵션:

```
--rule-only            LLM 없이 규칙 기반만
--model <tag>          Ollama 모델 지정
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

향후 계획: [`docs/ROADMAP.md`](docs/ROADMAP.md)

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

기여 및 작업 규칙: [`CLAUDE.md`](CLAUDE.md)

---

## 문서

| 문서 | 내용 |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | 실제 코드 기준 아키텍처 |
| [BENCHMARK.md](docs/BENCHMARK.md) | 측정 결과 |
| [BENCHMARK_SPEC.md](docs/BENCHMARK_SPEC.md) | 벤치마크 설계 명세 |
| [ISMS_P_COVERAGE.md](docs/ISMS_P_COVERAGE.md) | 인증 항목별 자동화 가능 여부 |
| [compliance_mapping.md](docs/compliance_mapping.md) | 매핑 상세 |
| [rules.md](docs/rules.md) | 커스텀 룰 작성 가이드 |
| [ROADMAP.md](docs/ROADMAP.md) | 향후 계획 |

---

## 라이선스

MIT
