import hashlib
import hmac
import os
from datetime import datetime
from typing import List

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

# Load environment variables from local .env file
load_dotenv()

# -----------------------------------------------------------------------------
# 1. DATABASE CONFIGURATION (SQLAlchemy + PostgreSQL)
# -----------------------------------------------------------------------------
# Railway automatically sets DATABASE_URL when you link a Postgres instance
DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://user:password@localhost:5432/telemetry_db"
)

# Fix for older Railway URL schemes starting with 'postgres://' instead of 'postgresql://'
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Define PostgreSQL Table Schema
class TelemetryRecord(Base):
    __tablename__ = "telemetry_logs"

    id = Column(Integer, primary_key=True, index=True)
    pilot_id = Column(String(50), nullable=False, index=True)
    batch_timestamp_ms = Column(Integer, nullable=False)
    raw_log = Column(Text, nullable=False)
    record_count = Column(Integer, nullable=False)
    signature_used = Column(String(64), nullable=False)
    received_at = Column(DateTime, default=datetime.utcnow)


# DB Dependency Injection
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -----------------------------------------------------------------------------
# 2. FASTAPI APP & SECURITY CONFIGURATION
# -----------------------------------------------------------------------------
app = FastAPI(title="Secure Telemetry Service")

RAW_SECRET = os.getenv("SHARED_SECRET", "MY_SECRET_FLIGHT_KEY_2026")
SHARED_SECRET = RAW_SECRET.encode("utf-8")


class TelemetryBundle(BaseModel):
    pilot_id: str
    timestamp_ms: int
    sha256_signature: str  # HMAC-SHA256 signature
    total_entries: int
    telemetry_log: List[str]


@app.on_event("startup")
def startup_event():
    # Force SQLAlchemy to establish Postgres connection and build tables on Railway boot
    Base.metadata.create_all(bind=engine)
    print("[DB] Telemetry tables initialized successfully.")


@app.get("/")
def health_check():
    return {"status": "online", "service": "ESP32 Telemetry Receiver"}


@app.post("/api/v1/telemetry/upload", status_code=status.HTTP_201_CREATED)
async def verify_and_store_telemetry(
    bundle: TelemetryBundle, db: Session = Depends(get_db)
):
    # 1. Reconstruct exact raw string formatting generated on SPIFFS
    raw_log_reconstructed = "\n".join(bundle.telemetry_log) + "\n"

    # 2. Compute HMAC-SHA256 signature using the shared secret
    computed_hmac = hmac.new(
        SHARED_SECRET, raw_log_reconstructed.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # 3. Constant-time comparison
    is_valid = hmac.compare_digest(
        computed_hmac.lower(), bundle.sha256_signature.lower()
    )

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTHENTICATION_FAILED",
                "message": "HMAC signature mismatch. Invalid key or tampered log.",
            },
        )

    # 4. PERSIST TO POSTGRESQL DATABASE
    db_record = TelemetryRecord(
        pilot_id=bundle.pilot_id,
        batch_timestamp_ms=bundle.timestamp_ms,
        raw_log=raw_log_reconstructed,
        record_count=bundle.total_entries,
        signature_used=computed_hmac,
    )

    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    # 5. Return success response (HTTP 201 Created)
    return {
        "status": "AUTHENTICATED_AND_VERIFIED",
        "record_id": db_record.id,
        "pilot_id": bundle.pilot_id,
        "records_logged": bundle.total_entries,
        "hmac_match": True,
        "signature": computed_hmac,
    }