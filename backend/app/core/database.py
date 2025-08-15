"""
Database configuration and session management for ScamSwatter
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from .config import settings

# Synchronous database engine
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=settings.MAX_CONNECTIONS_COUNT,
    max_overflow=0,
)

# Asynchronous database engine for high-performance operations
async_engine = create_async_engine(
    settings.DATABASE_URL_ASYNC,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=settings.MAX_CONNECTIONS_COUNT,
    max_overflow=0,
)

# Session factories
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
AsyncSessionLocal = sessionmaker(
    async_engine, class_=AsyncSession, expire_on_commit=False
)

# Base class for all database models
Base = declarative_base()


# Dependency to get database session
def get_db():
    """Dependency for getting synchronous database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_async_db():
    """Dependency for getting asynchronous database session"""
    async with AsyncSessionLocal() as session:
        yield session
