"""BENCHMARK: negative

주민등록번호를 AES(Fernet)로 암호화해서 저장하고, 로그에는 마스킹한 값만 남긴다.
positive/plaintext_pii.py 의 올바른 대조군이다.

예상: 탐지되지 않아야 한다. 개인정보 관련 룰이 컬럼명만 보고 오탐할 수 있다.
"""

import logging
import os
import sqlite3

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


def _cipher() -> Fernet:
    """환경변수에서 키를 읽어 암호화 객체를 만든다."""
    return Fernet(os.environ["PII_ENCRYPTION_KEY"].encode())


def mask_rrn(rrn: str) -> str:
    """주민등록번호를 마스킹한다 (앞 6자리만 노출)."""
    return f"{rrn[:6]}-*******"


def save_member(conn: sqlite3.Connection, name: str, rrn: str) -> None:
    """회원 정보를 저장한다. 주민등록번호는 암호화한다."""
    encrypted_rrn = _cipher().encrypt(rrn.encode())
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO members (name, rrn_encrypted) VALUES (?, ?)",
        (name, encrypted_rrn),
    )
    logger.info("회원 등록 완료: name=%s rrn=%s", name, mask_rrn(rrn))
    conn.commit()
