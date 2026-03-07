from __future__ import annotations

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings


Base = declarative_base()


def _engine_kwargs(url: str) -> dict:
    if url.startswith('sqlite'):
        return {'connect_args': {'check_same_thread': False}, 'future': True}
    return {'future': True, 'pool_pre_ping': True}


def _build_engine_with_fallback(primary_url: str):
    primary_engine = create_engine(primary_url, **_engine_kwargs(primary_url))
    try:
        with primary_engine.connect() as conn:
            conn.execute(text('SELECT 1'))
        return primary_engine, primary_url
    except SQLAlchemyError:
        if not primary_url.startswith('postgresql'):
            raise
        fallback_url = 'sqlite:///./osint.db'
        fallback_engine = create_engine(fallback_url, **_engine_kwargs(fallback_url))
        with fallback_engine.connect() as conn:
            conn.execute(text('SELECT 1'))
        return fallback_engine, fallback_url


engine, active_database_url = _build_engine_with_fallback(settings.database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
