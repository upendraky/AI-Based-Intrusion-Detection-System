from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    DateTime
)

from sqlalchemy.orm import (
    declarative_base,
    sessionmaker
)

from datetime import datetime


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DATABASE_URL = (
    "postgresql://localhost:5432/sentinel_ids"
)


# ============================================================
# DATABASE ENGINE
# ============================================================

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True
)


# ============================================================
# SESSION
# ============================================================

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


# ============================================================
# BASE
# ============================================================

Base = declarative_base()


# ============================================================
# DETECTION TABLE
# ============================================================

class Detection(Base):

    __tablename__ = "detections"


    id = Column(
        Integer,
        primary_key=True,
        index=True
    )


    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        index=True
    )


    prediction = Column(
        Integer,
        nullable=False
    )


    label = Column(
        String(50),
        nullable=False
    )


    confidence = Column(
        Float,
        nullable=False
    )


    threat_score = Column(
        Float,
        nullable=False
    )


    severity = Column(
        String(50),
        nullable=False
    )


    source = Column(
        String(255),
        default="CICIDS2017 Simulator"
    )


    status = Column(
        String(50),
        default="Detected"
    )


# ============================================================
# CREATE TABLES
# ============================================================

Base.metadata.create_all(
    bind=engine
)
