"""BENCHMARK: positive

f-string으로 사용자 입력을 SQL에 직접 삽입한다. 전형적인 SQL 인젝션이다.
"""

import sqlite3


def get_user(conn: sqlite3.Connection, user_id: str):
    """사용자를 조회한다."""
    cursor = conn.cursor()
    # VULN: isms_p=2.10.1 cwe=CWE-89 severity=high
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchone()


def search_users(conn: sqlite3.Connection, keyword: str):
    """키워드로 사용자를 검색한다."""
    cursor = conn.cursor()
    # VULN: isms_p=2.10.1 cwe=CWE-89 severity=high
    cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{keyword}%'")
    return cursor.fetchall()
