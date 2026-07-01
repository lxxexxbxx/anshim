"""
데이터베이스 연결 및 세션 관리.

SQLite 데이터베이스 연결, 초기화, 세션 팩토리를 제공합니다.
"""

import logging
import os
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from anshim.core.db.models import Base

logger = logging.getLogger(__name__)

# 기본 데이터베이스 경로: ~/.anshim/anshim.db
DEFAULT_DB_DIR = Path.home() / ".anshim"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "anshim.db"

# db_path별 엔진 및 세션 팩토리 캐시
# 주의: 과거에는 단일 전역 변수(_engine, _SessionFactory)로 구현되어 있어
# 서로 다른 db_path로 호출해도 최초 생성된 엔진만 재사용되는 버그가 있었음.
# (예: ScanRepository(path_a) 이후 ScanRepository(path_b)를 호출해도
#  내부적으로는 계속 path_a에 바인딩된 엔진을 사용 -> 잘못된/닫힌 DB에
#  쓰기를 시도하여 "attempt to write a readonly database" 등의 오류 발생)
# db_path를 캐시 키로 사용해 경로별로 별도의 엔진을 유지하도록 수정.
_engines: dict[str, Engine] = {}
_session_factories: dict[str, sessionmaker] = {}


def _cache_key(db_path: Path | None) -> str:
    """엔진 캐시에 사용할 키를 생성합니다.

    Args:
        db_path: 데이터베이스 파일 경로. None이면 기본 경로로 정규화.

    Returns:
        캐시 키 문자열.
    """
    resolved = db_path if db_path is not None else DEFAULT_DB_PATH
    return str(Path(resolved).resolve())


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


def get_engine(db_path: Path | None = None) -> Engine:
    """
    SQLAlchemy 엔진을 반환합니다.

    db_path별로 캐싱되어, 동일한 경로에 대해서는 같은 엔진 인스턴스를
    재사용하지만 서로 다른 경로에 대해서는 별도의 엔진을 생성합니다.
    """
    key = _cache_key(db_path)
    if key not in _engines:
        _engines[key] = create_engine(get_db_url(db_path), echo=False)
    return _engines[key]


def get_session_factory(db_path: Path | None = None) -> sessionmaker:
    """
    세션 팩토리를 반환합니다.

    Args:
        db_path: 데이터베이스 파일 경로.

    Returns:
        SQLAlchemy sessionmaker
    """
    key = _cache_key(db_path)
    if key not in _session_factories:
        engine = get_engine(db_path)
        _session_factories[key] = sessionmaker(bind=engine, expire_on_commit=False)
    return _session_factories[key]


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

    # 엔진 생성 및 테이블 초기화 (db_path별 캐시된 엔진 재사용)
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
    logger.info(f"데이터베이스 초기화 완료: {db_path}")

    # 보안: 데이터베이스 파일 권한 설정
    if db_path.exists():
        try:
            os.chmod(db_path, 0o600)
        except (OSError, AttributeError):
            pass


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
    모든 엔진과 세션 팩토리를 리셋합니다.

    테스트에서 사용됩니다. db_path별로 캐싱된 모든 엔진을 dispose하고
    캐시를 비웁니다.
    """
    for engine in _engines.values():
        engine.dispose()
    _engines.clear()
    _session_factories.clear()
