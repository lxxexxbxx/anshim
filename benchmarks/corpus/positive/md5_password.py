"""BENCHMARK: positive

비밀번호를 MD5로 해싱한다. MD5는 빠르고 충돌에 취약해 비밀번호 저장에 쓰면 안 된다.
negative/md5_checksum.py 와 대조하기 위한 파일이다. 같은 MD5지만 용도가 다르다.
"""

import hashlib


def hash_password(password: str) -> str:
    """비밀번호를 해싱한다."""
    # VULN: isms_p=2.7.1 cwe=CWE-327 severity=high
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password: str, stored_hash: str) -> bool:
    """비밀번호를 검증한다."""
    # VULN: isms_p=2.7.1 cwe=CWE-327 severity=high
    return hashlib.md5(password.encode()).hexdigest() == stored_hash
