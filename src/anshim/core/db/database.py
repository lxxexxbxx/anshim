"""
데이터베이스 연결 및 세션 관리.

SQLite 데이터베이스 연결, 초기화, 세션 팩토리를 제공합니다.
"""

import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from anshim.core.db.models import Base

logger = logging.getLogger(__name__)

# 기본 데이터베이스 경로: ~/.anshim/anshim.db
DEFAULT_DB_DIR = Path.home() / ".anshim"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "anshim.db"


def get_db_url(db_path: Path | None = None) -> str:
    """
    데이터베이스 URL을 반환합니다.

    Args:
        db_path: 데이터베이스 파일 경로. None이면 기본 경로 사용.

    Returns:
        SQLite 데이터베이스 URL
    """
    if db_path is None:
        db_path = DEFAULT_DB_PATH
    return f"sqlite:///{db_path}"


def init_db(db_path: Path | None = None) -> None:
    """
    데이터베이스를 초기화합니다.

    테이블이 없으면 생성하고, 디렉토리가 없으면 생성합니다.

    Args:
        db_path: 데이터베이스 파일 경로. None이면 기본 경로 사용.
    """
    if db_path is None:
        db_path = DEFAULT_DB_PATH

    # 디렉토리 생성
    db_dir = db_path.parent
    if not db_dir.exists():
        db_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"데이터베이스 디렉토리 생성: {db_dir}")

        # 보안: 사용자만 접근 가능하도록 권한 설정 (Unix 계열)
        try:
            os.chmod(db_dir, 0o700)
        except (OSError, AttributeError):
            # Windows에서는 chmod가 제한적으로 동작
            pass

    # 엔진 생성 및 테이블 초기화
    engine = create_engine(get_db_url(db_path), echo=False)
    Base.metadata.create_all(engine)
    logger.info(f"데이터베이스 초기화 완료: {db_path}")

    # 보안: 데이터베이스 파일 권한 설정
    if db_path.exists():
        try:
            os.chmod(db_path, 0o600)
        except (OSError, AttributeError):
            pass


# 전역 엔진 및 세션 팩토리
_engine = None
_SessionFactory = None


def get_engine(db_path: Path | None = None):
    """
    SQLAlchemy 엔진을 반환합니다.

    싱글톤 패턴으로 한 번만 생성됩니다.
    """
    global _engine
    if _engine is None:
        _engine = create_engine(get_db_url(db_path), echo=False)
    return _engine


def get_session_factory(db_path: Path | None = None) -> sessionmaker:
    """
    세션 팩토리를 반환합니다.

    Args:
        db_path: 데이터베이스 파일 경로.

    Returns:
        SQLAlchemy sessionmaker
    """
    global _SessionFactory
    if _SessionFactory is None:
        engine = get_engine(db_path)
        _SessionFactory = sessionmaker(bind=engine, expire_on_commit=False)
    return _SessionFactory


@contextmanager
def get_db(db_path: Path | None = None) -> Generator[Session, None, None]:
    """
    데이터베이스 세션 컨텍스트 매니저.

    사용 예:
        with get_db() as session:
            session.add(scan)
            session.commit()

    Args:
        db_path: 데이터베이스 파일 경로.

    Yields:
        SQLAlchemy Session
    """
    SessionFactory = get_session_factory(db_path)
    session = SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_engine() -> None:
    """
    엔진과 세션 팩토리를 리셋합니다.

    테스트에서 사용됩니다.
    """
    global _engine, _SessionFactory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionFactory = None
