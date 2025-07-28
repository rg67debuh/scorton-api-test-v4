from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

SQLITE_URL = "sqlite:///./test.db"
# POSTGRES_URL = "postgresql://postgres:postgres@localhost/"

engine = create_engine(SQLITE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
