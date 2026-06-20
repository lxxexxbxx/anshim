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

## 빠른 시작

### 설치

```bash
# uv 사용 (권장)
uv pip install anshim

# 또는 pip 사용
pip install anshim
```

### 초기 설정

```bash
# 하드웨어 감지 + 모델 추천 + 컴플라이언스 선택
anshim init
```

### 코드 스캔

```bash
# 기본 스캔 (ISMS-P + 하이브리드 분석)
anshim scan ./my-project

# 컴플라이언스 선택
anshim scan ./src --compliance isms              # ISMS만
anshim scan ./src --compliance isms-p,owasp      # ISMS-P + OWASP

# 특정 모델 사용
anshim scan ./src --model exaone3.5:7.8b

# Excel 리포트 생성
anshim scan ./src --excel
```

### 결과 확인

```bash
# 웹 대시보드 실행
anshim serve

# 리포트 목록 조회
anshim report list

# 특정 스캔 결과 조회
anshim report show <scan-id>
```

## CLI 명령어

| 명령어 | 설명 |
|--------|------|
| `anshim init` | 초기 설정 (하드웨어 감지, 모델 추천) |
| `anshim scan <dir>` | 디렉토리 보안 스캔 |
| `anshim serve` | 웹 대시보드 실행 (localhost:3000) |
| `anshim models list` | 설치된 모델 목록 |
| `anshim models pull <name>` | 모델 다운로드 |
| `anshim models recommend` | 하드웨어 기반 모델 추천 |
| `anshim report list` | 스캔 기록 목록 |
| `anshim report show <id>` | 스캔 결과 상세 조회 |
| `anshim report export <id>` | 리포트 내보내기 |

## 컴플라이언스 지원

| 컴플라이언스 | 항목 수 | 옵션 값 |
|--------------|---------|---------|
| ISMS | 80개 | `isms` |
| ISMS-P | 101개 | `isms-p` |
| OWASP Top 10 | 10개 | `owasp` |
| CWE Top 25 | 25개 | `cwe` |

```bash
# 복수 선택
anshim scan ./src --compliance isms-p,owasp,cwe

# 전체 선택
anshim scan ./src --compliance all
```

## 추천 모델

| GPU VRAM | 추천 모델 | 비고 |
|----------|-----------|------|
| >= 24GB | exaone3.5:32b, qwen2.5-coder:32b | 최고 품질 |
| 8-16GB | exaone3.5:7.8b, qwen2.5-coder:14b | 기본 추천 |
| 4-8GB | exaone3.5:2.4b, qwen2.5-coder:7b | 경량 |
| 없음 + RAM >= 16GB | exaone3.5:2.4b (CPU) | 느리지만 가능 |

## 개발 환경 설정

```bash
# 저장소 클론
git clone https://github.com/anshim/anshim.git
cd anshim

# 개발 의존성 설치 (uv 사용)
uv sync --dev

# 또는 pip 사용
pip install -e ".[dev]"

# 테스트 실행
pytest tests/

# 코드 포맷팅
ruff check --fix .
ruff format .

# 타입 체크
mypy anshim/
```

## 디렉토리 구조

```
anshim/
├── anshim/                    # 메인 패키지
│   ├── cli/                   # CLI 인터페이스
│   │   └── commands/          # 명령어 모듈
│   └── core/                  # 분석 엔진
│       ├── analyzers/         # 분석 모듈
│       ├── models/            # LLM 인터페이스
│       ├── compliance/        # 컴플라이언스 매핑
│       ├── reporters/         # 리포트 생성
│       ├── db/                # SQLite 모델
│       ├── prompts/           # LLM 프롬프트
│       └── utils/             # 유틸리티
├── rules/                     # 컴플라이언스 룰셋
│   ├── compliance/            # ISMS/ISMS-P
│   ├── owasp/                 # OWASP Top 10
│   └── cwe/                   # CWE Top 25
├── tests/                     # 테스트
├── docs/                      # 문서
└── web/                       # Next.js 대시보드 (예정)
```

## 라이센스

MIT License - 자유롭게 사용, 수정, 배포할 수 있습니다.

## 기여

이슈 리포트, 기능 제안, Pull Request를 환영합니다!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
