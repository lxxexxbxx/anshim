# AnShim (안심) — 한국 기업을 위한 AI 보안 코드 감사 도구

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Ollama](https://img.shields.io/badge/LLM-Ollama-black.svg)](https://ollama.com)
[![ISMS-P](https://img.shields.io/badge/컴플라이언스-ISMS--P-red.svg)](https://isms.kisa.or.kr)
[![Tests](https://img.shields.io/badge/tests-153%20passed-brightgreen.svg)]()

> **데이터를 외부로 보내지 않고, 한국어로, ISMS/ISMS-P에 매핑된 보안 감사 결과를 제공하는 오픈소스 SAST 도구**

---

## 핵심 차별점

기존 영문 SAST 도구(Semgrep, SonarQube, Snyk)와 달리:

| 기능 | AnShim | 기존 도구 |
|------|--------|----------|
| **ISMS/ISMS-P 자동 매핑** | ✅ 항목 번호 포함 | ❌ |
| **완전 로컬 LLM 분석** | ✅ 코드 외부 유출 없음 | ❌ 클라우드 전송 |
| **한국어 취약점 리포트** | ✅ | ❌ 영문만 |
| **공격 시나리오 생성** | ✅ (LLM) | 일부만 |
| **모델 자유 선택** | ✅ EXAONE, Qwen, Llama | ❌ |
| **오픈소스** | ✅ MIT | 일부만 |

---

## 30초 데모

```bash
# 설치
pip install -e .

# 초기 설정 (하드웨어 감지 → 모델 추천 → 설정 저장)
anshim init

# 취약한 Flask 앱 스캔 — 7개 취약점 탐지, ISMS-P 매핑 포함
anshim scan docs/demo/demo_target --compliance isms-p --open
```

**결과 예시:**
```
[AnShim] 분석 완료: 7건 발견
  ● [CRITICAL] 2.7.2  하드코딩된 시크릿 키 — app.py:13
  ● [CRITICAL] 2.11.1 MD5 비밀번호 해시 — app.py:65
  ● [CRITICAL] 3.3.1  주민번호 평문 저장 — app.py:72
  ● [HIGH]     2.10.1 SQL 인젝션 — app.py:115
  ● [HIGH]     2.10.2 XSS (Stored) — app.py:130
  ● [HIGH]     2.10.3 CSRF 미적용 — app.py:103
  ● [MEDIUM]   2.9.1  디버그 모드 활성화 — app.py:20

리포트 생성: reports/report_20260624_130000.html
```

---

## 아키텍처

```
┌─────────────────────────────────────────────────────────┐
│             사용자 인터페이스                            │
│    CLI (anshim)          Web Dashboard (Next.js)        │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│                 하이브리드 분석 엔진                      │
│                                                         │
│  RuleAnalyzer           LLMAnalyzer                     │
│  (Semgrep + Bandit)     (Ollama: EXAONE/Qwen)           │
│  빠른 패턴 매칭           FP 제거 + 공격 시나리오 생성    │
│       └──────────────────┘                              │
│                   ↓                                     │
│          ComplianceMapper                               │
│     ISMS / ISMS-P / OWASP / CWE 자동 매핑              │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│               리포트 & 스토리지                          │
│  HTML / Excel / JSON        SQLite (로컬)               │
└─────────────────────────────────────────────────────────┘

※ 외부 네트워크 통신 없음 — 모든 분석이 로컬에서 완결
```

---

## 설치 가이드

### 요구사항

- Python 3.10+
- (선택) [Ollama](https://ollama.com) — LLM 분석 사용 시
- (선택) Bandit — `pip install bandit`
- (선택) Semgrep — `pip install semgrep`

### 설치

```bash
# 저장소 클론
git clone https://github.com/your-id/anshim.git
cd anshim

# 패키지 설치
pip install -e .

# 설치 확인
anshim --version   # → anshim 0.2.0
```

### 초기 설정

```bash
anshim init
```

실행 시 자동으로:
1. GPU/RAM 감지 → 최적 모델 추천
2. Ollama 연결 상태 확인
3. `~/.anshim/config.yaml` 생성

---

## CLI 명령어

### 스캔

```bash
# 기본 스캔 (ISMS-P + 하이브리드 분석)
anshim scan ./my-project

# 규칙 기반만 (Ollama 없이 동작)
anshim scan ./src --rule-only

# 컴플라이언스 선택
anshim scan ./src --compliance isms              # ISMS (80개 항목)
anshim scan ./src --compliance isms-p            # ISMS-P (101개 항목, 기본값)
anshim scan ./src --compliance isms-p,owasp,cwe  # 복수 선택

# 스캔 옵션
anshim scan ./src --model exaone3.5:7.8b   # 모델 지정
anshim scan ./src --excel                   # Excel 리포트 추가 생성
anshim scan ./src --output ./reports        # 리포트 저장 경로
anshim scan ./src --severity high           # 심각도 필터
anshim scan ./src --open                    # 완료 후 브라우저 자동 오픈
```

### 모델 관리

```bash
anshim models list              # 설치된 모델 목록
anshim models list --all        # 지원 모델 전체 목록
anshim models pull exaone3.5:7.8b   # 모델 다운로드
anshim models recommend         # 하드웨어 기반 재추천
```

### 리포트 & 대시보드

```bash
anshim report list                      # 과거 스캔 목록
anshim report show <scan-id>            # 스캔 결과 상세 조회
anshim report export <scan-id> --excel  # Excel 내보내기
anshim serve                            # 웹 대시보드 (localhost:3000)
```

---

## 컴플라이언스 지원

### ISMS / ISMS-P (KISA 기준)

| 영역 | 항목 수 | ISMS | ISMS-P | AnShim 탐지 가능 |
|------|---------|------|--------|-----------------|
| 1. 관리체계 수립 및 운영 | 16개 | ✅ | ✅ | 범위 외 (코드 분석 불가) |
| 2. 보호대책 요구사항 | 64개 | ✅ | ✅ | **일부 탐지** |
| 3. 개인정보 처리 단계별 요구사항 | 21개 | ❌ | ✅ | **일부 탐지** |

코드 분석 가능한 항목만 다루고, 불가능한 항목(물리 보안, 조직 관리 등)은 "범위 외"로 표시합니다.

### 현재 구현 룰셋 (10개)

| ISMS-P 항목 | 취약점 | 심각도 |
|------------|--------|--------|
| 2.7.1 | 취약한 암호 알고리즘 (MD5, SHA1, DES) | HIGH |
| 2.7.2 | 암호키 하드코딩 | CRITICAL |
| 2.9.1 | 디버그 정보 외부 노출 | MEDIUM |
| 2.10.1 | SQL 인젝션 | CRITICAL |
| 2.10.2 | XSS (Reflected / Stored) | HIGH |
| 2.10.3 | CSRF 방어 미적용 | HIGH |
| 2.10.4 | 파일 업로드/다운로드 취약점 | HIGH |
| 2.11.1 | 비밀번호 평문/MD5 저장 | CRITICAL |
| 3.2.1 | 개인정보 암호화 미적용 | CRITICAL |
| 3.3.1 | 개인정보 보유 기간 미설정 | HIGH |

---

## 지원 언어

| 언어 | 규칙 기반 | LLM 기반 |
|------|----------|---------|
| Python | ✅ Bandit + Semgrep | ✅ |
| JavaScript / TypeScript | ✅ Semgrep | ✅ |
| Java | ✅ Semgrep | ✅ |

---

## 추천 LLM 모델

```
GPU VRAM ≥ 24GB  →  exaone3.5:32b / qwen2.5-coder:32b  (최고 품질)
GPU VRAM 8-16GB  →  exaone3.5:7.8b / qwen2.5-coder:14b (기본 추천 ⭐)
GPU VRAM 4-8GB   →  exaone3.5:2.4b / qwen2.5-coder:7b  (경량)
GPU 없음, RAM 16GB+  →  exaone3.5:2.4b (CPU 모드, 느림)
```

`anshim init`이 자동으로 하드웨어를 감지하고 최적 모델을 추천합니다.

---

## 설정 파일

`~/.anshim/config.yaml`:

```yaml
model: exaone3.5:7.8b       # 기본 LLM 모델
compliance: isms-p           # 기본 컴플라이언스
ollama_host: http://localhost:11434
db_path: ~/.anshim/anshim.db
```

CLI 플래그 > config.yaml > 기본값 순으로 우선순위가 결정됩니다.

---

## 개발 환경 설정

```bash
# 개발 의존성 설치
pip install -e ".[dev]"

# 테스트 실행
pytest tests/              # 153 tests passed

# 코드 포맷팅
ruff check --fix .
ruff format .

# 타입 체크
mypy .
```

---

## 프로젝트 구조

```
anshim/
├── cli/commands/          # init, scan, serve, models, report
├── core/
│   ├── analyzers/         # 규칙 기반, LLM, 하이브리드 분석기
│   ├── compliance/        # ISMS-P 컴플라이언스 매핑 엔진
│   ├── models/            # Ollama 클라이언트, 모델 레지스트리
│   ├── reporters/         # HTML / Excel / JSON 리포트
│   ├── db/                # SQLite ORM 모델
│   ├── prompts/ko/        # 한국어 LLM 프롬프트 템플릿
│   └── utils/             # 하드웨어 감지, 설정 관리
├── rules/
│   ├── compliance/        # ISMS-P 룰셋 YAML (10개)
│   ├── owasp/             # OWASP Top 10 룰셋
│   └── cwe/               # CWE Top 25 룰셋
├── docs/
│   ├── architecture.md    # 시스템 아키텍처
│   ├── compliance_mapping.md  # 컴플라이언스 매핑 상세
│   ├── rules.md           # 커스텀 룰 작성 가이드
│   ├── PORTFOLIO.md       # 포트폴리오 요약
│   └── demo/              # 데모 시나리오 + 취약한 샘플 앱
├── tests/                 # pytest (153 tests)
└── web/                   # Next.js 웹 대시보드
```

---

## 데모 실행

취약한 Flask 앱(SQLi, XSS, CSRF, MD5 해시, 하드코딩 키, 주민번호 평문 저장)을 포함한 데모:

```bash
# Windows
docs\demo\demo_scan.bat

# Linux / macOS
bash docs/demo/demo_scan.sh
```

자세한 시연 방법: [docs/demo/DEMO_SCRIPT.md](docs/demo/DEMO_SCRIPT.md)

---

## 문서

- [아키텍처 문서](docs/architecture.md)
- [컴플라이언스 매핑 가이드](docs/compliance_mapping.md)
- [커스텀 룰 작성 가이드](docs/rules.md)
- [포트폴리오 요약 (AhnLab CERT용)](docs/PORTFOLIO.md)

---

## 라이센스

MIT License — 기업 친화적, 상업적 이용 가능

## 기여

이슈 리포트, 기능 제안, Pull Request를 환영합니다.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-rule`)
3. Commit your changes (`git commit -m 'feat: 새 ISMS-P 룰 추가'`)
4. Push to the branch (`git push origin feature/new-rule`)
5. Open a Pull Request
