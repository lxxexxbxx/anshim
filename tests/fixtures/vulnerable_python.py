"""
취약한 Python 코드 샘플 (테스트용).

이 파일은 AnShim 분석기 테스트를 위한 의도적인 취약점을 포함합니다.
실제 프로젝트에서 사용하지 마세요!
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess
from typing import Any

# ============================================================
# 취약한 암호화 (ISMS 2.7.1 / CWE-327, CWE-328)
# ============================================================


def hash_password_md5(password: str) -> str:
    """취약한 MD5 해시 사용.

    MD5는 충돌 공격에 취약하므로 비밀번호 해싱에 사용해서는 안 됩니다.
    """
    return hashlib.md5(password.encode()).hexdigest()  # noqa: S324


def hash_password_sha1(password: str) -> str:
    """취약한 SHA1 해시 사용.

    SHA1도 충돌 공격에 취약합니다.
    """
    return hashlib.sha1(password.encode()).hexdigest()  # noqa: S324


# ============================================================
# SQL 인젝션 (ISMS 2.10.1 / CWE-89 / OWASP A03)
# ============================================================


def get_user_by_id_vulnerable(user_id: str) -> dict[str, Any] | None:
    """SQL 인젝션에 취약한 쿼리.

    사용자 입력이 직접 쿼리에 삽입되어 SQL 인젝션 공격에 취약합니다.
    """
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # 취약한 패턴: f-string으로 쿼리 구성
    query = f"SELECT * FROM users WHERE id = {user_id}"  # noqa: S608
    cursor.execute(query)

    return cursor.fetchone()


def search_users_vulnerable(name: str) -> list[dict[str, Any]]:
    """SQL 인젝션에 취약한 검색 쿼리."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # 취약한 패턴: 문자열 연결로 쿼리 구성
    query = "SELECT * FROM users WHERE name LIKE '%" + name + "%'"  # noqa: S608
    cursor.execute(query)

    return cursor.fetchall()


# ============================================================
# 명령어 인젝션 (CWE-78 / OWASP A03)
# ============================================================


def run_command_vulnerable(user_input: str) -> str:
    """명령어 인젝션에 취약한 코드.

    사용자 입력이 직접 쉘 명령에 삽입되어 명령어 인젝션에 취약합니다.
    """
    # 취약한 패턴: shell=True와 사용자 입력
    result = subprocess.run(  # noqa: S602
        f"echo {user_input}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def ping_host_vulnerable(host: str) -> str:
    """명령어 인젝션에 취약한 ping 함수."""
    # 취약한 패턴: os.system 사용
    os.system(f"ping -c 1 {host}")  # noqa: S605
    return "Done"


# ============================================================
# 하드코딩된 시크릿 (ISMS-P 3.2.1 / CWE-798)
# ============================================================

# 하드코딩된 API 키 (탐지되어야 함)
API_KEY = "sk-1234567890abcdef1234567890abcdef"  # noqa: S105
DATABASE_PASSWORD = "super_secret_password_123!"  # noqa: S105

# 하드코딩된 AWS 자격 증명
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # noqa: S105


def connect_to_database() -> None:
    """하드코딩된 비밀번호로 데이터베이스 연결."""
    password = "admin123"  # noqa: S105
    # 실제로는 연결하지 않음 (테스트용)
    print(f"Connecting with password: {password}")


# ============================================================
# 안전하지 않은 역직렬화 (CWE-502)
# ============================================================


def load_user_data_vulnerable(data: bytes) -> Any:
    """안전하지 않은 pickle 역직렬화.

    pickle.loads는 임의 코드 실행에 취약합니다.
    """
    return pickle.loads(data)  # noqa: S301


# ============================================================
# assert 문 사용 (CWE-617)
# ============================================================


def check_admin_vulnerable(user: dict[str, Any]) -> bool:
    """프로덕션 코드에서 assert 사용.

    assert 문은 -O 플래그로 비활성화될 수 있어 보안 검사에 부적합합니다.
    """
    assert user.get("role") == "admin", "Admin only!"  # noqa: S101
    return True


# ============================================================
# 안전한 코드 예시 (비교용)
# ============================================================


def hash_password_secure(password: str) -> str:
    """안전한 비밀번호 해싱.

    SHA-256 또는 bcrypt를 사용해야 합니다.
    """
    # 실제로는 bcrypt나 argon2를 사용해야 함
    return hashlib.sha256(password.encode()).hexdigest()


def get_user_by_id_secure(user_id: int) -> dict[str, Any] | None:
    """안전한 파라미터화된 쿼리."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # 안전한 패턴: 파라미터화된 쿼리
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

    return cursor.fetchone()
