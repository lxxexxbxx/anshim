"""BENCHMARK: negative

SQLAlchemy ORM만 사용하며 raw SQL이 없다. 정상 대조군이다.

예상: 탐지되지 않아야 한다. 여기서 탐지가 나오면 규칙셋이 과하다는 신호다.
"""

from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class User(Base):
    """사용자 테이블."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String(50))
    status = Column(String(20))


def get_active_users(database_url: str, keyword: str) -> list[User]:
    """활성 사용자를 이름으로 검색한다."""
    engine = create_engine(database_url)
    session = sessionmaker(bind=engine)()
    try:
        return (
            session.query(User)
            .filter(User.status == "active")
            .filter(User.name.like(f"%{keyword}%"))
            .all()
        )
    finally:
        session.close()
