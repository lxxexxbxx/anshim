"""BENCHMARK: negative

비밀번호를 bcrypt로 해싱한다. salt가 자동 적용되고 work factor를 지정한다.
positive/md5_password.py 의 올바른 대조군이다.

예상: 탐지되지 않아야 한다.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """비밀번호를 해싱한다."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))


def verify_password(password: str, stored_hash: bytes) -> bool:
    """비밀번호를 검증한다."""
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)
