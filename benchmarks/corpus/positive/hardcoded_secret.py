"""BENCHMARK: positive

운영 코드에 API 키와 DB 비밀번호가 하드코딩되어 있다.
negative/secret_from_env.py, negative/test_fixture_secret.py 와 대조된다.

주의: 아래 값들은 의도적으로 실제 서비스의 키 형식을 흉내내지 않는다.
공개 저장소에 실제 결제 서비스의 운영 키 형식을 그대로 흉내낸 문자열을 두면
비밀 정보 스캐너가 진짜 유출과 구분하지 못하고, 푸시 자체가 차단된다.
탐지는 Bandit B105 가 변수명으로 수행하므로 값 형식과 무관하다.
"""

import httpx

# VULN: isms_p=2.7.2 cwe=CWE-798 severity=critical
STRIPE_SECRET_KEY = "BENCHMARK-FAKE-VALUE-NOT-A-REAL-KEY"
# VULN: isms_p=2.7.2 cwe=CWE-798 severity=critical
DB_PASSWORD = "BENCHMARK-FAKE-VALUE-NOT-A-REAL-PASSWORD"


def charge(amount_krw: int) -> httpx.Response:
    """결제를 요청한다."""
    return httpx.post(
        "https://api.stripe.example/v1/charges",
        headers={"Authorization": f"Bearer {STRIPE_SECRET_KEY}"},
        data={"amount": amount_krw, "currency": "krw"},
    )


def dsn() -> str:
    """운영 DB 접속 문자열을 만든다."""
    return f"postgresql://svc_app:{DB_PASSWORD}@db.internal:5432/prod"
