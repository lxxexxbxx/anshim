"""BENCHMARK: positive

문자열 연결로 SQL을 조립한다. f-string과 형태만 다른 같은 취약점이다.
"""

import sqlite3


def delete_order(conn: sqlite3.Connection, order_id: str):
    """주문을 삭제한다."""
    cursor = conn.cursor()
    # VULN: isms_p=2.10.1 cwe=CWE-89 severity=high
    cursor.execute("DELETE FROM orders WHERE id = " + order_id)
    conn.commit()


def count_by_status(conn: sqlite3.Connection, status: str):
    """상태별 주문 수를 센다."""
    cursor = conn.cursor()
    query = "SELECT COUNT(*) FROM orders WHERE status = '%s'" % status
    # VULN: isms_p=2.10.1 cwe=CWE-89 severity=high
    cursor.execute(query)
    return cursor.fetchone()[0]
