# AnShim 아키텍처 문서

## 전체 시스템 구조

```
┌─────────────────────────────────────────────────────────────────────┐
│                        사용자 인터페이스 레이어                        │
│                                                                     │
│   CLI (anshim scan / init / serve / models / report)               │
│   Web Dashboard (Next.js, localhost:3000)                           │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│                         서비스 레이어                                 │
│                                                                     │
│   ScanService          ReportService        ModelService            │
│   (스캔 오케스트레이션)   (리포트 생성)        (모델 관리)              │
└───────────┬─────────────────┬──────────────────┬───────────────────┘
            │                 │                  │
┌───────────▼─────────────────▼──────────────────▼───────────────────┐
│                           코어 레이어                                 │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │                    HybridAnalyzer                       │        │
│  │  ┌────────────────┐    ┌────────────────────────────┐   │        │
│  │  │  RuleAnalyzer  │    │      LLMAnalyzer           │   │        │
│  │  │ (Semgrep/      │    │  (Ollama: EXAONE/Qwen)     │   │        │
│  │  │  Bandit 래퍼)  │    │  - False Positive 제거     │   │        │
│  │  │                │    │  - 공격 시나리오 생성       │   │        │
│  │  │  빠른 1차 스캔  │    │  - 수정 방법 제안 (한국어) │   │        │
│  │  └───────┬────────┘    └──────────┬─────────────────┘   │        │
│  │          └──────────┬─────────────┘                      │        │
│  │                     ▼                                     │        │
│  │           ComplianceMapper                                │        │
│  │           (ISMS / ISMS-P / OWASP / CWE 매핑)             │        │
│  └─────────────────────────────────────────────────────────┘        │
│                                                                     │
│  ┌────────────────┐  ┌────────────────┐  ┌─────────────────┐        │
│  │  HTMLReporter  │  │  ExcelReporter │  │  JSONReporter   │        │
│  │  (Jinja2)      │  │  (openpyxl)    │  │  (기계 처리용)  │        │
│  └────────────────┘  └────────────────┘  └─────────────────┘        │
│                                                                     │
│  ┌──────────────────────────────────────┐                           │
│  │              Utils                   │                           │
│  │  HardwareDetector  ConfigManager     │                           │
│  └──────────────────────────────────────┘                           │
└─────────────────────────────┬───────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────────┐
│                         스토리지 레이어                               │
│                                                                     │
│   SQLite (~/.anshim/anshim.db)          Rules (YAML 파일)           │
│   - ScanResult                          - rules/compliance/         │
│   - Vulnerability                       - rules/owasp/              │
│   - ComplianceMapping                   - rules/cwe/                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 분석 파이프라인 흐름도

```
anshim scan ./src
      │
      ▼
 [1] 파일 수집
      파일 목록 추출 (.py, .js, .ts, .java)
      GitHistoryAnalyzer로 변경 이력 조회 (옵션)
      │
      ▼
 [2] 규칙 기반 분석 (빠름, ~1-5초)
      Semgrep → 취약한 패턴 매칭
      Bandit → Python 보안 이슈 탐지
      규칙 YAML 메타데이터 → ISMS/OWASP 매핑
      │
      ▼
 [3] LLM 기반 분석 (깊음, ~30-120초)
      취약점 코드 컨텍스트 추출
      EXAONE/Qwen 프롬프트 생성 (core/prompts/ko/)
      Ollama API 호출 (localhost:11434)
      ├── False Positive 필터링
      ├── 공격 시나리오 생성 (한국어)
      └── 구체적 수정 방법 생성 (한국어)
      │
      ▼
 [4] 컴플라이언스 매핑
      applicable_to 메타데이터로 필터링
      --compliance 옵션에 따라:
        isms    → 2.x 항목만
        isms-p  → 2.x + 3.x 항목
        owasp   → OWASP A01-A10
        cwe     → CWE Top 25
      │
      ▼
 [5] 결과 저장 및 리포트 생성
      SQLite 저장 (scan_results, vulnerabilities)
      HTML 리포트 (Jinja2 템플릿)
      Excel 리포트 (openpyxl, --excel 옵션)
      JSON 리포트 (--json 옵션)
      │
      ▼
 [6] 완료
      리포트 경로 출력
      --open 옵션 시 브라우저 자동 오픈
      anshim serve로 웹 대시보드 확인
```

---

## 컴포넌트별 역할

### CLI 레이어 (`cli/commands/`)

| 명령어 | 파일 | 역할 |
|--------|------|------|
| `anshim init` | `init.py` | 하드웨어 감지, 모델 추천, 설정 저장 |
| `anshim scan` | `scan.py` | 스캔 오케스트레이션, 리포트 생성 |
| `anshim serve` | `serve.py` | Next.js 웹 대시보드 실행 |
| `anshim models` | `models.py` | Ollama 모델 목록/다운로드/추천 |
| `anshim report` | `report.py` | 과거 스캔 결과 조회/내보내기 |

### 코어 레이어 (`core/`)

| 모듈 | 역할 |
|------|------|
| `analyzers/rule_based.py` | Semgrep, Bandit 실행 및 결과 파싱 |
| `analyzers/llm_based.py` | Ollama API 호출, 프롬프트 관리 |
| `analyzers/hybrid.py` | 두 분석기 조합, 중복 제거 |
| `compliance/mapper.py` | YAML 룰 로드, 취약점 ↔ 컴플라이언스 매핑 |
| `models/ollama_client.py` | Ollama HTTP 클라이언트 |
| `models/registry.py` | 지원 모델 목록, 하드웨어별 추천 |
| `reporters/html_reporter.py` | Jinja2 기반 HTML 리포트 |
| `reporters/excel_reporter.py` | openpyxl 기반 Excel 리포트 |
| `db/models.py` | SQLAlchemy ORM 모델 |
| `utils/hardware.py` | GPU/RAM 감지, 모델 추천 |
| `utils/config_manager.py` | ~/.anshim/config.yaml 관리 |

### 웹 레이어 (`web/`)

Next.js 14 App Router 기반 SPA. FastAPI(`core/api/`)와 통신.

| 경로 | 역할 |
|------|------|
| `/` | 스캔 목록, 통계 대시보드 |
| `/scans/[id]` | 개별 스캔 상세 결과 |
| `core/api/` | FastAPI REST API (anshim serve) |

---

## 데이터 흐름

```
소스코드 파일 (로컬)
    │
    │  [규칙 기반]          [LLM 기반]
    ├─→ Semgrep/Bandit ──→ 결과 JSON
    │                           │
    │                    Ollama (localhost)
    │                    EXAONE / Qwen
    │                           │
    └─→ 취약점 목록 ←──── 심층 분석 결과
              │
              ▼
        YAML 룰셋 메타데이터
        ISMS-P / OWASP / CWE 매핑
              │
              ▼
        SQLite 저장          HTML / Excel 리포트
        (~/.anshim/          (로컬 파일)
         anshim.db)
              │
              ▼
        FastAPI REST API
              │
              ▼
        Next.js 웹 대시보드
        (localhost:3000)
```

**외부 통신은 일절 없음** — 모든 분석이 로컬에서 완결됩니다.

---

## 보안 설계 원칙

1. **데이터 로컬 처리**: 소스코드, 분석 결과 모두 외부로 전송하지 않음
2. **최소 권한**: SQLite 파일 권한 600 (사용자 홈 디렉토리)
3. **입력 검증**: 경로 탐색(Path Traversal) 방어, 파일 확장자 화이트리스트
4. **LLM 프롬프트 인젝션 방어**: 코드 내용을 백틱/구분자로 격리
5. **localhost 바인딩**: 웹 대시보드는 기본적으로 127.0.0.1만 허용
6. **로그 민감 정보 제외**: 코드 내용, 취약점 상세를 로그에 기록하지 않음

---

## 확장 포인트

### 새 분석기 추가
`core/analyzers/` 아래 `BaseAnalyzer`를 상속하고 `analyze()` 메서드 구현.

### 새 컴플라이언스 룰 추가
`rules/compliance/` 아래 YAML 파일 추가. `applicable_to` 필드 필수.

### 새 리포터 추가
`core/reporters/` 아래 `BaseReporter`를 상속하고 `generate()` 메서드 구현.

### 새 LLM 모델 추가
`core/models/registry.py`의 `MODEL_REGISTRY`에 모델 정보 추가.
