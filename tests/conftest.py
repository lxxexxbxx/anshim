"""
pytest 공통 fixtures.

테스트에서 사용하는 공통 설정과 픽스처를 정의합니다.
"""

import tempfile
from pathlib import Path
from typing import Generator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from anshim.core.db.database import reset_engine
from anshim.core.db.models import Base


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """임시 디렉토리를 생성합니다."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_db_path(temp_dir: Path) -> Path:
    """임시 데이터베이스 경로를 반환합니다."""
    return temp_dir / "test.db"


@pytest.fixture
def db_session(temp_db_path: Path) -> Generator[Session, None, None]:
    """
    테스트용 데이터베이스 세션을 생성합니다.

    각 테스트마다 새로운 인메모리 DB를 사용합니다.
    """
    # 전역 엔진 리셋
    reset_engine()

    # 테스트용 인메모리 DB
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)

    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    session = SessionLocal()

    try:
        yield session
    finally:
        session.close()
        engine.dispose()
        reset_engine()


@pytest.fixture
def sample_scan_data() -> dict:
    """샘플 스캔 데이터를 반환합니다."""
    return {
        "id": "test-scan-001",
        "target_path": "/tmp/test-project",
        "status": "completed",
        "total_files": 10,
        "total_vulnerabilities": 3,
        "critical_count": 1,
        "high_count": 1,
        "medium_count": 1,
        "low_count": 0,
    }


@pytest.fixture
def sample_vulnerability_data() -> dict:
    """샘플 취약점 데이터를 반환합니다."""
    return {
        "rule_id": "2.10.1-sql-injection",
        "title": "SQL Injection 취약점",
        "description": "사용자 입력이 SQL 쿼리에 직접 사용되어 SQL Injection 공격에 취약합니다.",
        "file_path": "/tmp/test-project/app.py",
        "line_start": 42,
        "line_end": 45,
        "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        "attack_scenario": "공격자가 user_id에 악성 SQL을 주입하여 데이터베이스 전체를 탈취할 수 있습니다.",
        "remediation": "파라미터화된 쿼리를 사용하세요.",
        "remediation_code": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    }
