"""BENCHMARK: positive

주민등록번호와 휴대폰 번호를 평문으로 저장하고 로그에 남긴다.
ISMS-P 3.x(개인정보 처리) 영역에 해당한다.
"""

import logging
import sqlite3

logger = logging.getLogger(__name__)


def save_member(conn: sqlite3.Connection, name: str, rrn: str, phone: str) -> None:
    """회원 정보를 저장한다."""
    cursor = conn.cursor()
    # VULN: isms_p=3.2.1 cwe=CWE-311 severity=critical
    cursor.execute(
        "INSERT INTO members (name, rrn, phone) VALUES (?, ?, ?)",
        (name, rrn, phone),
    )
    # VULN: isms_p=3.3.1 cwe=CWE-532 severity=high
    logger.info("회원 등록 완료: name=%s rrn=%s phone=%s", name, rrn, phone)
    conn.commit()
