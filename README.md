# AnShim (안심)

> 한국 기업을 위한 로컬 LLM 기반 보안 코드 감사 도구

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**AnShim**은 데이터를 외부로 보내지 않고, 한국어로, ISMS / ISMS-P 컴플라이언스에 매핑된 코드 보안 감사 결과를 제공하는 오픈소스 도구입니다.

## 주요 특징

- **한국 컴플라이언스 특화** - ISMS, ISMS-P, 개인정보보호법, 정통망법 자동 매핑
- **데이터 외부 유출 ZERO** - 100% 로컬 LLM 사용 (Ollama 기반)
- **모델 사용자 선택 가능** - EXAONE, Qwen, Llama, DeepSeek 등 자유 선택
- **한국어 리포트** - Excel, HTML, 웹 대시보드 모두 한국어 기본
- **하이브리드 분석** - 규칙 기반(Semgrep/Bandit) + LLM 심층 분석

---

## 설치 가이드 (Windows)

### 사전 요구사항

1. **Python 3.10+** — https://www.python.org/downloads/
2. **Ollama** (LLM 분석 사용 시) — https://ollama.com
3. **Semgrep** (선택, 규칙 기반 분석 강화) — `pip install semgrep`
4. **Bandit** (선택, Python 보안 분석) — `pip install bandit`

### 설치 방법

```bash
# 1. 저장소 클론
git clone https://github.com/anshim/anshim.git
cd anshim

# 2. 패키지 설치
pip install -e .

# 3. 설치 확인
anshim --version
```

### 빠른 시작 (3단계)

```bash
# 1단계: 초기 설정 (하드웨어 감지 + 모델 추천 + DB 초기화)
anshim init

# 2단계: 코드 스캔
anshim scan ./my-project

# 3단계: 웹 대시보드로 결과 확인
anshim serve
```

---

## CLI 명령어

### 스캔

```bash
# 기본 스캔 (ISMS-P + 하이브리드 분석)
anshim scan ./my-project

# 규칙 기반만 (Semgrep/Bandit, Ollama 불필요)
anshim scan ./src --rule-only

# 컴플라이언스 선택
anshim scan ./src --compliance isms              # ISMS만 (80개 항목)
anshim scan ./src --compliance isms-p            # ISMS-P (101개 항목, 기본값)
anshim scan ./src --compliance isms-p,owasp,cwe  # 복수 선택

# 특정 모델 사용
anshim scan ./src --model exaone3.5:7.8b

# Excel 리포트 + 스캔 완료 시 브라우저 자동 오픈
anshim scan ./src --excel --open

# 리포트 저장 경로 지정
anshim scan ./src --output ./reports

# 심각도 필터 (critical/high만 표시)
anshim scan ./src --severity high
```

### 모델 관리

```bash
anshim models list           # 설치된 모델 목록
anshim models list --all     # 지원 모델 전체 목록
anshim models pull exaone3.5:7.8b   # 모델 다운로드
anshim models recommend      # 하드웨어 기반 모델 추천
```

### 리포트 관리

```bash
anshim report list                    # 과거 스캔 목록
anshim report show <scan-id>          # 특정 스캔 결과 조회
anshim report export <scan-id> --excel  # Excel로 내보내기
```

### 웹 대시보드

```bash
anshim serve              # localhost:3000 에서 대시보드 실행
```

---

## CLI 명령어 요약

| 명령어 | 설명 |
|--------|------|
| `anshim init` | 초기 설정 (하드웨어 감지, 모델 추천, DB 초기화) |
| `anshim scan <dir>` | 디렉토리 보안 스캔 |
| `anshim serve` | 웹 대시보드 실행 (localhost:3000) |
| `anshim models list` | 설치된 모델 목록 |
| `anshim models pull <name>` | 모델 다운로드 |
| `anshim models recommend` | 하드웨어 기반 모델 추천 |
| `anshim report list` | 스캔 기록 목록 |
| `anshim report show <id>` | 스캔 결과 상세 조회 |

---

## 컴플라이언스 지원

| 컴플라이언스 | 항목 수 | 옵션 값 |
|--------------|---------|---------|
| ISMS | 80개 | `isms` |
| ISMS-P | 101개 | `isms-p` |
| OWASP Top 10 | 10개 | `owasp` |
| CWE Top 25 | 25개 | `cwe` |

---

## 추천 모델

| GPU VRAM | 추천 모델 | 비고 |
|----------|-----------|------|
| >= 24GB | exaone3.5:32b, qwen2.5-coder:32b | 최고 품질 |
| 8-16GB | exaone3.5:7.8b, qwen2.5-coder:14b | 기본 추천 ⭐ |
| 4-8GB | exaone3.5:2.4b, qwen2.5-coder:7b | 경량 |
| 없음 + RAM >= 16GB | exaone3.5:2.4b (CPU) | 느리지만 가능 |
| RAM < 16GB | — | 권장하지 않음 |

`anshim init` 또는 `anshim models recommend` 실행 시 자동으로 감지하여 추천합니다.

---

## 설정 파일

`anshim init` 실행 후 `~/.anshim/config.yaml`에 기본 설정이 저장됩니다.

```yaml
# ~/.anshim/config.yaml 예시
model: exaone3.5:7.8b       # 기본 LLM 모델
compliance: isms-p           # 기본 컴플라이언스
ollama_host: http://localhost:11434
db_path: ~/.anshim/anshim.db
```

CLI 플래그 > config.yaml > 하드코딩 기본값 순서로 우선순위가 결정됩니다.

---

## 개발 환경 설정

```bash
# 저장소 클론
git clone https://github.com/anshim/anshim.git
cd anshim

# 개발 의존성 설치
pip install -e ".[dev]"

# 테스트 실행
pytest tests/

# 코드 포맷팅
ruff check --fix .
ruff format .

# 타입 체크
mypy .
```

---

## 디렉토리 구조

```
anshim/
├── cli/                   # CLI 인터페이스
│   └── commands/          # init, scan, serve, models, report 명령어
├── core/                  # 분석 엔진
│   ├── analyzers/         # 규칙 기반, LLM, 하이브리드 분석기
│   ├── models/            # Ollama 클라이언트, 모델 레지스트리
│   ├── compliance/        # 컴플라이언스 매핑 엔진
│   ├── reporters/         # HTML, Excel, JSON 리포트 생성
│   ├── db/                # SQLite 모델, 스키마
│   ├── prompts/ko/        # 한국어 LLM 프롬프트 템플릿
│   └── utils/             # 하드웨어 감지, 설정 관리
├── rules/                 # 컴플라이언스 룰셋 (YAML)
│   ├── compliance/        # ISMS/ISMS-P 룰
│   ├── owasp/             # OWASP Top 10 룰
│   └── cwe/               # CWE Top 25 룰
├── tests/                 # pytest 테스트
└── web/                   # Next.js 웹 대시보드
```

---

## 라이센스

MIT License — 자유롭게 사용, 수정, 배포할 수 있습니다.

## 기여

이슈 리포트, 기능 제안, Pull Request를 환영합니다!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: 기능 추가'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
