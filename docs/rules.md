# AnShim 커스텀 룰 작성 가이드

## 개요

AnShim의 룰셋은 YAML 파일로 관리됩니다.
새 보안 룰을 추가하려면 적절한 디렉토리에 YAML 파일을 만들면 됩니다.

> **⚠️ 중요: 이 YAML 룰은 Semgrep 룰 형식이 아닙니다.**
> `rules/owasp/`, `rules/cwe/`, `rules/compliance/`의 YAML 파일은 Semgrep이
> 직접 실행하는 탐지 규칙이 아니라, **컴플라이언스 매핑용 메타데이터**입니다
> (`core/compliance/loader.py`가 읽어서 ISMS/ISMS-P 항목과 매핑하는 데 사용).
> 실제 정적 분석(코드 탐지)은 Semgrep CLI가 자체 레지스트리 설정
> (`p/python`, `p/javascript` 등)을 사용해 별도로 수행하며, Bandit은
> 자체 내장 룰을 사용합니다. 즉 이 디렉토리에 룰을 추가해도 Semgrep/Bandit의
> 탐지 결과 자체는 늘어나지 않으며, 탐지된 `rule_id`(예: `CWE-89-sql-injection`,
> `2.10.1-sql-injection`)와 매칭되는 항목이 있을 때만 컴플라이언스 항목이
> 리포트에 표시됩니다. 자세한 매칭 방식은 `docs/compliance_mapping.md` 참고.

---

## 디렉토리 구조

```
rules/
├── compliance/
│   ├── 2.x_protection_measures/   # ISMS & ISMS-P 공통 룰
│   └── 3.x_personal_info/         # ISMS-P 전용 룰 (개인정보)
├── owasp/                         # OWASP Top 10 룰
└── cwe/                           # CWE Top 25 룰
```

### 어느 디렉토리에 배치할지

| 적용 범위 | 디렉토리 |
|-----------|----------|
| ISMS + ISMS-P 공통 | `rules/compliance/2.x_protection_measures/` |
| ISMS-P 전용 (개인정보) | `rules/compliance/3.x_personal_info/` |
| OWASP 기반 | `rules/owasp/` |
| CWE 기반 | `rules/cwe/` |

---

## YAML 룰 파일 전체 스키마

```yaml
# ───────────── 기본 정보 ─────────────
id: "2.10.1-sql-injection"           # 고유 ID (디렉토리 없이 파일명 기준)
title: "SQL 인젝션"                   # 한국어 제목
description: |                       # 상세 설명 (여러 줄 가능)
  사용자 입력을 직접 SQL 쿼리에 삽입하는 경우 탐지.
  공격자가 인증 우회, 데이터 조회/수정/삭제 가능.

# ───────────── 적용 범위 ─────────────
# 반드시 하나 이상 명시 (없으면 룰 로드 안 됨)
applicable_to:
  - isms       # ISMS 항목 (2.x)
  - isms-p     # ISMS-P 항목 (2.x + 3.x)
  - owasp      # OWASP 기반 룰
  - cwe        # CWE 기반 룰

# ───────────── 메타데이터 ─────────────
category: "2.10 시스템 및 서비스 보안관리"  # ISMS-P 카테고리
subcategory: "2.10.1 보안 요구사항 검토"    # 세부 항목

severity: high   # critical / high / medium / low / info

languages:       # 지원 언어
  - python
  - java
  - javascript

# ───────────── 탐지 도구 매핑 ─────────────
# Semgrep 룰 ID (선택 - 해당 없으면 빈 배열)
semgrep_rule_ids:
  - "python.django.security.audit.avoid-insecure-deserialization"

# Bandit 테스트 ID (Python 전용, 선택)
bandit_test_ids:
  - "B608"   # hardcoded_sql_expressions

# ───────────── 패턴 예시 ─────────────
# 취약한 코드 패턴 (시연/교육용)
vulnerable_patterns:
  python:
    - "query = f\"SELECT * FROM users WHERE id = {user_id}\""
    - "cursor.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")"
  java:
    - "stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + userId);"
  javascript:
    - "db.query(`SELECT * FROM users WHERE id = ${userId}`);"

# 안전한 코드 패턴 (권장 예시)
safe_patterns:
  python:
    - "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))"
    - "cursor.execute(\"SELECT * FROM users WHERE name = %s\", (name,))"
  java:
    - "PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");"
    - "stmt.setInt(1, userId);"
  javascript:
    - "db.query('SELECT * FROM users WHERE id = ?', [userId]);"

# ───────────── 수정 권장사항 ─────────────
remediation:
  ko: |
    Prepared Statement(파라미터화 쿼리)를 사용하세요:

    Python:
      cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

    Java:
      PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
      stmt.setInt(1, userId);

    ORM 사용 시 (가장 안전):
      User.query.filter_by(id=user_id).first()  # SQLAlchemy

  en: |
    Use parameterized queries (Prepared Statements):
    Never concatenate user input directly into SQL strings.

# ───────────── 교차 매핑 ─────────────
cwe_ids:
  - "CWE-89"    # SQL Injection

owasp_ids:
  - "A03:2021"  # Injection

# ───────────── 한국 법규 (선택) ─────────────
korean_regulations:
  - "개인정보보호법 제29조 (안전조치의무)"

# ───────────── 참조 자료 ─────────────
references:
  - https://www.kisa.or.kr/public/laws/laws3.jsp
  - https://owasp.org/www-community/attacks/SQL_Injection
  - https://cwe.mitre.org/data/definitions/89.html
```

---

## 파일 명명 규칙

```
<ISMS항목번호>-<영문-식별자>.yaml

예시:
  2.7.1-weak-cryptography.yaml      # ISMS 2.7.1 항목
  2.10.1-sql-injection.yaml          # ISMS 2.10.1 항목
  3.2.1-personal-info-encryption.yaml # ISMS-P 3.2.1 항목

OWASP / CWE:
  A03-injection.yaml                 # OWASP A03
  CWE-89-sql-injection.yaml          # CWE-89
```

---

## 룰 작성 체크리스트

룰 파일 추가 전 반드시 확인:

- [ ] `id` 필드가 고유한가?
- [ ] `applicable_to` 필드가 있는가? (isms / isms-p / owasp / cwe 중 하나 이상)
- [ ] `severity` 수준이 실제 위험도에 맞는가?
- [ ] `languages` 목록이 정확한가?
- [ ] `remediation.ko` (한국어 수정 방법)가 있는가?
- [ ] `cwe_ids`와 `owasp_ids`가 매핑되었는가?
- [ ] ISMS-P 전용 룰은 `3.x_personal_info/` 디렉토리에 있는가?
- [ ] ISMS/ISMS-P 공통 룰은 `2.x_protection_measures/` 디렉토리에 있는가?

---

## 룰 테스트

새 룰 추가 후 테스트:

```bash
# 룰 로드 확인
python -c "from anshim.core.compliance.mapper import ComplianceMapper; m = ComplianceMapper(); print(m.load_rules())"

# 데모 앱에 적용해서 탐지 확인
anshim scan docs/demo/demo_target --compliance isms-p --rule-only

# 단위 테스트
pytest tests/test_compliance.py -v
```

---

## 자주 사용하는 severity 기준

| 수준 | 기준 | 예시 |
|------|------|------|
| `critical` | 즉각적 데이터 유출/시스템 침해 가능 | SQL 인젝션, 하드코딩 자격증명 |
| `high` | 심각한 보안 위협, 악용 시나리오 존재 | XSS, CSRF, 파일 업로드 |
| `medium` | 보안 약화, 조합 시 위협 | 디버그 노출, 취약한 암호 알고리즘 |
| `low` | 보안 모범 사례 위반 | 불필요한 주석, 미약한 검증 |
| `info` | 참고 정보 | 외부 라이브러리 사용, 버전 노출 |
