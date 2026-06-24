# AnShim 컴플라이언스 매핑 가이드

## 개요

AnShim은 코드 분석으로 탐지 가능한 보안 취약점을 한국 컴플라이언스 기준에 자동으로 매핑합니다.

---

## 지원 컴플라이언스

| 컴플라이언스 | 항목 수 | 설명 | CLI 옵션 |
|---|---|---|---|
| ISMS | 80개 | 정보보호관리체계 인증 | `--compliance isms` |
| ISMS-P | 101개 | 개인정보보호 관리체계 (ISMS + 개인정보) | `--compliance isms-p` |
| OWASP Top 10 | 10개 | 웹 애플리케이션 10대 보안 취약점 | `--compliance owasp` |
| CWE Top 25 | 25개 | 가장 위험한 소프트웨어 취약점 25종 | `--compliance cwe` |

> ISMS-P는 ISMS의 상위 호환입니다. ISMS-P 인증 시 ISMS 80개 항목이 자동으로 충족됩니다.

---

## ISMS / ISMS-P 구조

KISA 기준 총 101개 항목 (ISMS 80개 + ISMS-P 전용 21개):

```
1. 관리체계 수립 및 운영 (16개) ─── ISMS & ISMS-P 공통
   1.1 관리체계 기반 마련
   1.2 위험 관리
   1.3 관리체계 운영
   1.4 관리체계 점검 및 개선

2. 보호대책 요구사항 (64개) ─────── ISMS & ISMS-P 공통
   2.1 정책, 조직, 자산 관리
   2.2 인적 보안
   2.3 외부자 보안
   2.4 물리 보안
   2.5 인증 및 권한관리        ← 코드 분석 가능
   2.6 접근통제                ← 코드 분석 가능
   2.7 암호화 적용             ← 코드 분석 가능
   2.8 정보시스템 도입 및 개발 보안 ← 코드 분석 가능
   2.9 시스템 및 서비스 운영관리    ← 코드 분석 가능
   2.10 시스템 및 서비스 보안관리   ← 코드 분석 가능
   2.11 사고 예방 및 대응
   2.12 재해복구

3. 개인정보 처리 단계별 요구사항 (21개) ─ ISMS-P 전용
   3.1 개인정보 수집 시 보호조치    ← 코드 분석 가능
   3.2 개인정보 보유 및 이용 시 보호조치 ← 코드 분석 가능
   3.3 개인정보 제공 시 보호조치    ← 코드 분석 가능
   3.4 개인정보 파기 시 보호조치    ← 코드 분석 가능
   3.5 정보주체 권리보호
```

---

## 코드 분석으로 탐지 가능한 항목

코드 수준에서 검증 가능한 항목만 AnShim이 다룹니다.
코드 외 영역(물리 보안, 조직 관리 등)은 리포트에 "범위 외" 표시됩니다.

### 탐지 가능 항목

| 항목 | 설명 | AnShim 룰 |
|------|------|-----------|
| 2.5 인증 및 권한관리 | 인증 우회, 하드코딩 자격증명 | `2.11.1-weak-password` |
| 2.6 접근통제 | 인가 우회, Path Traversal | `2.10.4-file-upload` |
| 2.7 암호화 적용 | 취약한 암호 알고리즘, 키 관리 | `2.7.1-weak-cryptography`, `2.7.2-hardcoded-keys` |
| 2.8 개발 보안 | 입력 검증, 코드 보안 | `2.10.1-sql-injection`, `2.10.2-xss` |
| 2.9 운영관리 | 디버그 노출, 로깅 취약점 | `2.9.1-debug-exposure` |
| 2.10 보안관리 | SQLi, XSS, CSRF, 파일 업로드 | `2.10.1` ~ `2.10.4` |
| 3.1~3.4 개인정보 처리 | 개인정보 암호화, 보유 기간 | `3.2.1-personal-info-encryption`, `3.3.1-personal-info-storage` |

### 탐지 불가능 항목 (코드 범위 밖)

- 1.x 관리체계 수립 (정책 문서, 위험 관리 절차)
- 2.1~2.4 정책/조직/물리 보안
- 2.11~2.12 사고 대응, 재해복구
- 3.5 정보주체 권리보호 (운영 절차)

---

## 룰셋 메타데이터 구조

각 YAML 룰 파일의 주요 필드:

```yaml
id: 2.7.1-weak-cryptography
title: 취약한 암호 알고리즘 사용
description: |
  MD5, SHA1 등 취약한 해시 함수 또는 DES, RC4 사용 탐지.

# 적용 범위 (필수)
applicable_to:
  - isms      # ISMS만
  - isms-p    # ISMS + ISMS-P

severity: high           # critical / high / medium / low / info
languages: [python, java, javascript]

# 분석 도구 매핑
semgrep_rule_ids:
  - "python.cryptography.security.insecure-hash-md5"
bandit_test_ids:
  - "B303"

# CWE / OWASP 교차 매핑
cwe_ids:
  - "CWE-327"
owasp_ids:
  - "A02:2021"

# 한국어 수정 권장사항
remediation:
  ko: |
    SHA-256 이상의 안전한 알고리즘을 사용하세요.
```

---

## --compliance 옵션 동작 방식

```
--compliance isms
  → applicable_to에 'isms' 포함된 룰만 로드
  → 1.x 범위 외 항목 표시

--compliance isms-p
  → applicable_to에 'isms' 또는 'isms-p' 포함된 룰 전체 로드
  → 3.x 개인정보 항목 포함

--compliance isms-p,owasp,cwe
  → 위 + OWASP Top 10 + CWE Top 25 룰 추가 로드
  → 가장 포괄적인 분석

--compliance all
  → 모든 룰 로드 (isms-p,owasp,cwe와 동일)
```

---

## 현재 룰셋 현황

### ISMS / ISMS-P 공통 (2.x_protection_measures/)

| 파일 | 항목 | 심각도 |
|------|------|--------|
| `2.7.1-weak-cryptography.yaml` | 취약한 암호 알고리즘 | HIGH |
| `2.7.2-hardcoded-keys.yaml` | 암호키 하드코딩 | CRITICAL |
| `2.9.1-debug-exposure.yaml` | 디버그 정보 노출 | MEDIUM |
| `2.10.1-sql-injection.yaml` | SQL 인젝션 | CRITICAL |
| `2.10.2-xss.yaml` | 크로스사이트 스크립팅 | HIGH |
| `2.10.3-csrf.yaml` | CSRF 방어 미적용 | HIGH |
| `2.10.4-file-upload.yaml` | 파일 업로드/다운로드 취약점 | HIGH |
| `2.11.1-weak-password.yaml` | 취약한 패스워드 저장 | CRITICAL |

### ISMS-P 전용 (3.x_personal_info/)

| 파일 | 항목 | 심각도 |
|------|------|--------|
| `3.2.1-personal-info-encryption.yaml` | 개인정보 암호화 미적용 | CRITICAL |
| `3.3.1-personal-info-storage.yaml` | 개인정보 보유 기간 미설정 | HIGH |

### OWASP Top 10 (owasp/)

| 파일 | OWASP 항목 |
|------|-----------|
| `A01-broken-access-control.yaml` | A01:2021 접근 제어 취약점 |
| `A02-cryptographic-failures.yaml` | A02:2021 암호화 실패 |
| `A03-injection.yaml` | A03:2021 인젝션 |
| `A07-authentication-failure.yaml` | A07:2021 인증 실패 |
| `A09-logging-monitoring.yaml` | A09:2021 로깅/모니터링 실패 |

### CWE Top 25 (cwe/)

| 파일 | CWE |
|------|-----|
| `CWE-79-xss.yaml` | XSS |
| `CWE-89-sql-injection.yaml` | SQL 인젝션 |
| `CWE-798-hardcoded-credentials.yaml` | 하드코딩 자격증명 |

---

## 커스텀 룰 추가

새 룰 추가 방법은 [docs/rules.md](./rules.md)를 참조하세요.
