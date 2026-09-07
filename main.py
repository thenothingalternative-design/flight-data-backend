import hashlib
import hmac
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import BigInteger, Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

load_dotenv()

# -----------------------------------------------------------------------------
# 1. DATABASE CONFIGURATION
# -----------------------------------------------------------------------------
DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://user:password@localhost:5432/telemetry_db"
)

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class TelemetryRecord(Base):
    __tablename__ = "telemetry_logs"

    id              = Column(Integer,    primary_key=True, index=True)
    pilot_id        = Column(String(50), nullable=False,   index=True)
    batch_timestamp = Column(BigInteger, nullable=False)               # millis() or Unix ms — won't overflow
    raw_log         = Column(Text,       nullable=False)
    record_count    = Column(Integer,    nullable=False)
    signature_used  = Column(String(64), nullable=False)
    received_at     = Column(DateTime,   default=datetime.utcnow)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -----------------------------------------------------------------------------
# 2. APP STARTUP / SHUTDOWN
# -----------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    print("[DB] Telemetry tables initialized.")
    yield
    # (add any shutdown cleanup here if needed)


app = FastAPI(title="Secure Telemetry Service", lifespan=lifespan)

RAW_SECRET    = os.getenv("SHARED_SECRET", "MY_SECRET_FLIGHT_KEY_2026")
SHARED_SECRET = RAW_SECRET.encode("utf-8")


# -----------------------------------------------------------------------------
# 3. REQUEST SCHEMA
# -----------------------------------------------------------------------------
class TelemetryBundle(BaseModel):
    pilot_id:        str
    timestamp_ms:    int
    sha256_signature: str
    total_entries:   int
    telemetry_log:   List[str]

    @field_validator("pilot_id")
    @classmethod
    def pilot_id_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("pilot_id must not be empty")
        return v.strip()

    @field_validator("total_entries")
    @classmethod
    def entries_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("total_entries must be > 0")
        return v


# -----------------------------------------------------------------------------
# 4. ROUTES
# -----------------------------------------------------------------------------
@app.get("/")
def health_check():
    return {"status": "online", "service": "ESP32 Telemetry Receiver"}


@app.post("/api/v1/telemetry/upload", status_code=status.HTTP_201_CREATED)
async def verify_and_store_telemetry(
    bundle: TelemetryBundle, db: Session = Depends(get_db)
):
    # ── Validate entry count matches actual log length ────────────────────────
    if bundle.total_entries != len(bundle.telemetry_log):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "ENTRY_COUNT_MISMATCH",
                "message": f"total_entries={bundle.total_entries} but log has {len(bundle.telemetry_log)} lines",
            },
        )

    # ── Reconstruct raw CSV bytes exactly as the ESP32 wrote them to SPIFFS ──
    # ESP32 writes each line as "...\n", readStringUntil('\n') strips the \n,
    # trim() removes any \r, so rejoining with \n and a final \n reproduces
    # the original file byte-for-byte.
    raw_log_reconstructed = "\n".join(bundle.telemetry_log) + "\n"

    # ── Compute HMAC-SHA256 ───────────────────────────────────────────────────
    computed_hmac = hmac.new(
        SHARED_SECRET,
        raw_log_reconstructed.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # ── Constant-time comparison (prevents timing attacks) ───────────────────
    if not hmac.compare_digest(computed_hmac.lower(), bundle.sha256_signature.lower()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTHENTICATION_FAILED",
                "message": "HMAC signature mismatch — invalid key or tampered log.",
                # During development only — remove before production:
                "debug_computed": computed_hmac,
                "debug_received": bundle.sha256_signature,
            },
        )

    # ── Persist to PostgreSQL ─────────────────────────────────────────────────
    db_record = TelemetryRecord(
        pilot_id        = bundle.pilot_id,
        batch_timestamp = bundle.timestamp_ms,
        raw_log         = raw_log_reconstructed,
        record_count    = bundle.total_entries,
        signature_used  = computed_hmac,
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    return {
        "status":       "AUTHENTICATED_AND_VERIFIED",
        "record_id":    db_record.id,
        "pilot_id":     bundle.pilot_id,
        "records_logged": bundle.total_entries,
        "hmac_match":   True,
        "signature":    computed_hmac,
    }
