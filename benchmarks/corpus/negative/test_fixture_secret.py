"""BENCHMARK: negative

규칙 기반이 오탐하기 쉬운 핵심 케이스.

테스트 코드 안의 더미 자격증명이다. 실제 서비스에 존재하지 않는 값이며
테스트 더블(mock 서버)만 사용한다. 유출되어도 위험이 없다.
positive/hardcoded_secret.py 와 형태는 같고 맥락이 다르다.

예상: 하드코딩 시크릿 룰이 문자열 패턴만 보고 탐지한다.
      LLM이 "테스트 픽스처이므로 실제 위험이 아니다"를 판별해야 한다.
"""

import pytest

# 아래 값은 모두 테스트 전용 더미다. 실제 발급된 키가 아니다.
FAKE_API_KEY = "BENCHMARK-FAKE-TEST-KEY-0000"
FAKE_DB_PASSWORD = "test-password-not-real"


@pytest.fixture
def api_client():
    """테스트용 API 클라이언트를 만든다 (mock 서버 대상)."""
    return {
        "base_url": "http://localhost:9999",
        "api_key": FAKE_API_KEY,
    }


def test_authorization_header(api_client):
    """인증 헤더가 올바르게 구성되는지 확인한다."""
    header = f"Bearer {api_client['api_key']}"
    assert header.startswith("Bearer BENCHMARK-FAKE-")
