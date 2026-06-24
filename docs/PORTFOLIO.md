# AnShim 포트폴리오 요약

> AhnLab CERT 인턴십 지원용 프로젝트 소개 문서

---

## 프로젝트 개요

**AnShim(안심)**은 한국 기업의 ISMS/ISMS-P 인증 준비를 지원하는 **로컬 LLM 기반 SAST(정적 분석 보안 테스팅) 도구**입니다.

- **기간**: 2025년 12월 ~ 2026년 6월 (약 7개월, 1인 개발)
- **GitHub**: [github.com/your-id/anshim](https://github.com/your-id/anshim)
- **기술 스택**: Python, Flask, Next.js, SQLite, Ollama, Semgrep, Bandit

---

## 개발 배경 및 문제 의식

기존 SAST 도구(Semgrep, SonarQube, Snyk)에는 세 가지 한계가 있습니다:

1. **한국 컴플라이언스 미지원**: ISMS/ISMS-P 항목 자동 매핑 불가
2. **클라우드 의존**: 소스코드를 외부 서버로 전송 → 기밀 코드 유출 위험
3. **영문 리포트**: 국내 개발팀이 바로 활용하기 어려움

AnShim은 이 세 가지 문제를 동시에 해결합니다.

---

## 핵심 기능 및 기술적 도전

### 1. 하이브리드 분석 엔진

**규칙 기반(Semgrep/Bandit) + LLM(EXAONE/Qwen)** 2단계 분석:

```
소스코드 → Semgrep/Bandit (빠른 패턴 매칭)
                ↓
         LLM (Ollama, 로컬)
         - False Positive 필터링
         - 공격 시나리오 생성
         - 한국어 수정 제안
                ↓
         ISMS-P 컴플라이언스 자동 매핑
```

**기술적 도전**: Semgrep의 JSON 출력을 파싱하여 YAML 룰 메타데이터와 결합, LLM 프롬프트 인젝션 방어(코드 내 악성 주석 격리)

### 2. ISMS/ISMS-P 컴플라이언스 매핑 엔진

각 취약점 YAML에 `applicable_to: [isms, isms-p]` 메타데이터를 두어 필터링:

```yaml
# ISMS-P 전용 (3.x 개인정보 처리)
id: 3.2.1-personal-info-encryption
applicable_to:
  - isms-p     # ISMS 스캔 시 자동 제외
severity: critical
```

101개 ISMS-P 항목 중 코드로 검증 가능한 30여 개 항목을 선별, 10개 룰셋 구현.

**기술적 도전**: ISMS vs ISMS-P 항목 구분, 코드 분석 가능/불가능 항목 분류

### 3. 완전 로컬 LLM 파이프라인

Ollama API(localhost:11434)를 통해 EXAONE 3.5 7.8B 모델로 코드 분석:

```python
# 외부 API 호출 제로 - 모든 분석 로컬
response = requests.post(
    "http://localhost:11434/api/generate",
    json={"model": "exaone3.5:7.8b", "prompt": prompt}
)
```

하드웨어 자동 감지 후 최적 모델 추천 (VRAM 8GB → EXAONE 7.8B 등).

**기술적 도전**: LG AI Research의 EXAONE 모델 한국어 성능 검증, 모델별 프롬프트 최적화

### 4. 한국어 취약점 리포트

Jinja2 HTML 템플릿 + openpyxl Excel 리포트:

- ISMS-P 항목 번호 (2.10.1, 3.2.1 등) 자동 태깅
- 공격 시나리오 한국어 서술
- 수정 방법 구체적 코드 예시 (한국어)
- 심각도별 차트 (recharts, 웹 대시보드)

---

## 구현 결과

| 항목 | 수치 |
|------|------|
| 구현 룰셋 | 10개 (ISMS-P 10개) + OWASP 5개 + CWE 3개 |
| 지원 언어 | Python, JavaScript/TypeScript, Java |
| 테스트 통과율 | 153 tests passed, 0 failed |
| CLI 명령어 | 5개 (init / scan / serve / models / report) |
| 데모 취약점 앱 | 취약점 7종 포함 Flask 앱 |

---

## CERT 직무 연관성

### 취약점 분석 역량

- SQL 인젝션, XSS, CSRF, Path Traversal, 암호화 취약점 직접 구현 및 탐지 룰 작성
- OWASP Top 10, CWE Top 25 기반 룰셋 설계
- 공격 시나리오 자동 생성 파이프라인 구축

### 컴플라이언스 이해

- ISMS/ISMS-P 101개 항목 분석 및 코드 레벨 매핑 가능 항목 선별
- 개인정보보호법, 정통망법 관련 조항 코드 탐지 룰 구현
- KISA 보안 가이드라인 실제 적용

### 보안 자동화

- CI/CD 통합 가능한 CLI 도구 (SARIF 출력 예정)
- 대규모 코드베이스 자동 스캔 파이프라인
- 룰셋 YAML 기반 플러그인 구조로 확장 가능

### 로컬 LLM 활용

- 기업 내 코드 보안 감사 시 외부 유출 없는 AI 분석
- EXAONE(LG AI Research) 한국어 특화 모델 활용
- False Positive 감소를 위한 LLM 검증 레이어

---

## 기술 스택 심층

```
Python 3.10+     핵심 분석 엔진, CLI (Click)
SQLAlchemy       ORM, SQLite 관리
Ollama           로컬 LLM 런타임
Semgrep          정적 분석 (300+ 룰)
Bandit           Python 보안 분석
Next.js 14       웹 대시보드 (App Router)
FastAPI          REST API 서버
Jinja2           HTML 리포트 템플릿
openpyxl         Excel 리포트
pytest           153개 테스트
ruff             린터/포매터
```

---

## 향후 개선 계획 (v2)

1. **GitHub Actions 통합** - PR마다 자동 보안 스캔, SARIF 리포트
2. **VS Code 익스텐션** - 실시간 취약점 하이라이팅
3. **더 많은 언어 지원** - Go, Rust, C/C++
4. **KISA 신규 가이드라인 반영** - 클라우드 보안, API 보안
5. **멀티 모델 앙상블** - 여러 LLM 결과 투표 방식으로 정확도 향상

---

## 데모

```bash
# 설치 및 데모 실행
git clone https://github.com/your-id/anshim.git
cd anshim
pip install -e .
anshim init

# 취약한 Flask 앱 스캔 (7개 취약점 탐지)
anshim scan docs/demo/demo_target --compliance isms-p --open

# 또는 원클릭 데모
docs\demo\demo_scan.bat    # Windows
bash docs/demo/demo_scan.sh  # Linux/macOS
```

**예상 탐지 결과:**
- CRITICAL 3건 (하드코딩 키, MD5 해시, 주민번호 평문)
- HIGH 3건 (SQL 인젝션, XSS, CSRF)
- MEDIUM 1건 (디버그 모드)

모두 ISMS-P 항목 번호와 함께 한국어로 보고됩니다.
