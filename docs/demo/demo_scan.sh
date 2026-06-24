#!/usr/bin/env bash
# AnShim 데모 실행 스크립트 (Linux / macOS)
# 이 스크립트는 취약한 Flask 앱을 스캔하고 HTML 리포트를 자동으로 엽니다.

set -e

echo ""
echo "============================================="
echo "  AnShim (안심) - 보안 코드 감사 도구 데모"
echo "============================================="
echo ""

# 1. anshim 명령어 확인
if ! command -v anshim &> /dev/null; then
    echo "[오류] anshim이 설치되어 있지 않습니다."
    echo "  설치: pip install -e ."
    echo "  (anshim/ 디렉토리에서 실행)"
    exit 1
fi

echo "[1/4] AnShim 버전 확인..."
anshim --version
echo ""

# 2. 데모 대상 경로 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_TARGET="$SCRIPT_DIR/demo_target"
REPORT_DIR="$SCRIPT_DIR/reports"

echo "[2/4] 데모 대상: $DEMO_TARGET"
echo "      리포트 저장: $REPORT_DIR"
echo ""

# 3. 규칙 기반 스캔 실행
echo "[3/4] 규칙 기반 스캔 실행 중... (--rule-only 모드)"
echo "      대상: docs/demo/demo_target/app.py"
echo "      컴플라이언스: ISMS-P + OWASP + CWE"
echo ""

anshim scan "$DEMO_TARGET" \
    --compliance isms-p,owasp,cwe \
    --rule-only \
    --output "$REPORT_DIR" \
    --open

echo ""
echo "[4/4] 스캔 완료!"
echo ""
echo "발견되어야 할 주요 취약점:"
echo "  [CRITICAL] 2.7.2  하드코딩된 시크릿 키 (SECRET_KEY, DB_PASSWORD, API_KEY)"
echo "  [CRITICAL] 2.11.1 MD5 비밀번호 해시 (hashlib.md5 사용)"
echo "  [CRITICAL] 3.3.1  개인정보(주민번호, 카드번호) 평문 저장"
echo "  [HIGH]     2.10.1 SQL 인젝션 (f-string 쿼리 직접 사용)"
echo "  [HIGH]     2.10.2 XSS (| safe 필터로 비이스케이프 렌더링)"
echo "  [HIGH]     2.10.3 CSRF 토큰 미적용"
echo "  [MEDIUM]   2.9.1  디버그 모드 활성화 (debug=True)"
echo ""
echo "HTML 리포트가 브라우저에서 열렸습니다."
echo "웹 대시보드: anshim serve"
echo ""
