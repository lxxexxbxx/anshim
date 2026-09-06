"""BENCHMARK: negative

값은 전부 파라미터 바인딩으로 넘긴다. 테이블명만 포맷 문자열로 조합하는데,
허용 목록에 있는 이름만 통과시키므로 사용자 입력이 SQL에 직접 들어가지 않는다.

예상: "포맷 문자열 + execute" 패턴이라 규칙이 SQL 인젝션으로 오탐하기 쉽다.
      LLM이 "값은 파라미터화되어 있고 테이블명은 화이트리스트다"를 판별해야 한다.
"""

import sqlite3

_ALLOWED_TABLES = frozenset({"users", "orders", "products"})


def count_rows(conn: sqlite3.Connection, table: str, status: str) -> int:
    """지정한 테이블에서 상태별 행 수를 센다."""
    if table not in _ALLOWED_TABLES:
        raise ValueError(f"허용되지 않은 테이블: {table}")

    cursor = conn.cursor()
    query = f"SELECT COUNT(*) FROM {table} WHERE status = ?"
    cursor.execute(query, (status,))
    return cursor.fetchone()[0]


def get_user(conn: sqlite3.Connection, user_id: str):
    """사용자를 조회한다."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
