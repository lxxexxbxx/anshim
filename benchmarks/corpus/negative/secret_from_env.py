"""BENCHMARK: negative

시크릿을 환경변수에서 읽는다. os.getenv의 두 번째 인자는 로컬 개발용
플레이스홀더이며 운영에서는 환경변수가 반드시 주입된다.
운영 환경에서 기본값이 그대로 쓰이면 예외를 던져 조기에 실패시킨다.

예상: 기본값 문자열이 하드코딩 시크릿으로 오탐될 수 있다.
"""

import os

_DEV_PLACEHOLDER = "dev-placeholder-not-a-real-secret"


def api_key() -> str:
    """API 키를 반환한다."""
    value = os.getenv("ANSHIM_API_KEY", _DEV_PLACEHOLDER)
    if value == _DEV_PLACEHOLDER and os.getenv("ENV") == "production":
        raise RuntimeError("운영 환경에 ANSHIM_API_KEY가 설정되지 않았습니다")
    return value


def database_url() -> str:
    """DB 접속 문자열을 반환한다."""
    return os.environ["DATABASE_URL"]
