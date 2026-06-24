# AnShim 데모 시연 스크립트

> **용도**: AnShim을 처음 보는 면접관/청중에게 핵심 기능을 5분 안에 보여주는 시나리오

---

## 시연 준비 (2분)

```bash
# 1. 설치 확인
anshim --version  # → anshim 0.2.0

# 2. Bandit 확인 (규칙 기반 분석용)
bandit --version

# 3. 데모 앱 위치 확인
ls docs/demo/demo_target/  # → app.py, requirements.txt
```

---

## 시나리오: 취약한 Flask 앱 감사

### Step 1. 데모 앱 소개 (30초)

> "이 Flask 앱은 실제 개발자들이 흔히 저지르는 보안 실수들을 의도적으로 포함시켰습니다.
> 로그인 기능, 게시판, 검색 기능이 있는 단순한 웹앱처럼 보이지만..."

```bash
# app.py의 핵심 취약점 보여주기
cat docs/demo/demo_target/app.py | head -30
```

**강조 포인트:**
- `SECRET_KEY = "super-secret-key-12345"` → 하드코딩된 시크릿 키
- `app.config["DEBUG"] = True` → 디버그 모드
- `hashlib.md5(password.encode())` → 취약한 MD5 해시

---

### Step 2. AnShim 스캔 실행 (1분)

```bash
anshim scan docs/demo/demo_target \
    --compliance isms-p,owasp,cwe \
    --rule-only \
    --open
```

**화면에 보이는 내용:**
```
[AnShim] 분석 시작: docs/demo/demo_target
[AnShim] 파일 발견: 1개 (Python)
[AnShim] Bandit 분석 중...
[AnShim] 컴플라이언스 매핑 중... (ISMS-P, OWASP, CWE)
[AnShim] 취약점 발견: 7건 (CRITICAL: 3, HIGH: 3, MEDIUM: 1)
[AnShim] 리포트 생성: report_20240624_130000.html
[AnShim] 브라우저 자동 오픈...
```

---

### Step 3. HTML 리포트 설명 (2분)

브라우저가 자동으로 열린 후 각 섹션 설명:

**1. 요약 대시보드**
- 취약점 심각도별 분류 (CRITICAL 3건 강조)
- ISMS-P 항목 매핑 표

**2. 핵심 취약점 하이라이트**

| 심각도 | ISMS-P | 취약점 | 위치 |
|--------|--------|--------|------|
| CRITICAL | 2.7.2 | 하드코딩된 시크릿 키 | app.py:13-15 |
| CRITICAL | 2.11.1 | MD5 비밀번호 해시 | app.py:65 |
| CRITICAL | 3.3.1 | 주민번호 평문 저장 | app.py:72-74 |
| HIGH | 2.10.1 | SQL 인젝션 | app.py:115 |
| HIGH | 2.10.2 | XSS (Stored) | app.py:130 |
| HIGH | 2.10.3 | CSRF 미적용 | app.py:103 |
| MEDIUM | 2.9.1 | 디버그 모드 | app.py:20 |

**3. 수정 제안 (한국어)**
- 각 취약점마다 구체적인 수정 코드 예시
- ISMS-P 조항 번호와 설명 포함

---

### Step 4. 차별점 강조 (1분)

> "일반 영문 도구들과 다른 점이 세 가지입니다."

1. **한국 컴플라이언스 자동 매핑**
   - "이 취약점은 ISMS-P 2.10.1 항목 위반입니다"
   - 기업이 바로 감사 보고서에 활용 가능

2. **완전 로컬 실행**
   - 코드가 외부 서버에 1바이트도 나가지 않음
   - Ollama로 LLM 분석도 로컬에서

3. **한국어 리포트**
   - 개발팀이 바로 읽고 수정 가능
   - 영문 번역 불필요

---

## 시연 후 Q&A 예상 질문

**Q: LLM 분석은 어떻게 다른가요?**
> A: 규칙 기반(Semgrep/Bandit)이 빠른 패턴 매칭이라면, LLM은 문맥을 이해해서 False Positive를 줄이고 공격 시나리오를 생성합니다.
> `anshim scan ./src`로 실행하면 Ollama(EXAONE)가 각 취약점의 실제 악용 시나리오를 한국어로 작성해줍니다.

**Q: 실제 기업에서 사용하려면 어떻게 하나요?**
> A: `pip install anshim`, `anshim init`으로 하드웨어에 맞는 모델 자동 설치, `anshim scan ./src`로 바로 시작 가능합니다.
> Docker 이미지로도 배포 가능합니다.

**Q: Semgrep과 차이점은?**
> A: Semgrep은 영문 기준, OWASP 기반입니다. AnShim은 ISMS/ISMS-P 한국 컴플라이언스 매핑, 한국어 리포트, 로컬 LLM 조합이 차별점입니다.

---

## 원클릭 데모 실행

```bash
# Windows
docs\demo\demo_scan.bat

# Linux / macOS
bash docs/demo/demo_scan.sh
```
