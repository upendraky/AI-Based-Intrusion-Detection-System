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
import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
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


    # --------------------------------------------------------
    # ID
    # --------------------------------------------------------

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )


    # --------------------------------------------------------
    # TIMESTAMP
    # --------------------------------------------------------

    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        index=True
    )


    # --------------------------------------------------------
    # ML PREDICTION
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # SOURCE / STATUS
    # --------------------------------------------------------

    source = Column(
        String(255),
        default="CICIDS2017 Simulator"
    )


    status = Column(
        String(50),
        default="Detected"
    )


    # ========================================================
    # LIVE NETWORK METADATA
    # ========================================================

    src_ip = Column(
        String(45),
        nullable=True
    )


    dst_ip = Column(
        String(45),
        nullable=True
    )


    src_port = Column(
        Integer,
        nullable=True
    )


    dst_port = Column(
        Integer,
        nullable=True
    )


    protocol = Column(
        String(20),
        nullable=True
    )


    packet_count = Column(
        Integer,
        nullable=True
    )


    byte_count = Column(
        Integer,
        nullable=True
    )


    duration = Column(
        Float,
        nullable=True
    )


# ============================================================
# CREATE TABLES
# ============================================================

Base.metadata.create_all(
    bind=engine
)