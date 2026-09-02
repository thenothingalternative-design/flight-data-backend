import hashlib
import hmac
import os
from typing import List
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

# Load environment variables from local .env file
load_dotenv()

app = FastAPI(title="Secure Telemetry Service")

# Read secret key from environment variable, falling back to a default key
RAW_SECRET = os.getenv("SHARED_SECRET", "MY_SECRET_FLIGHT_KEY_2026")
SHARED_SECRET = RAW_SECRET.encode("utf-8")


class TelemetryBundle(BaseModel):
    pilot_id: str
    timestamp_ms: int
    sha256_signature: str  # HMAC-SHA256 signature
    total_entries: int
    telemetry_log: List[str]


@app.get("/")
def health_check():
    return {"status": "online", "service": "ESP32 Telemetry Receiver"}


@app.post("/api/v1/telemetry/upload")
async def verify_and_store_telemetry(bundle: TelemetryBundle):
    # Reconstruct exact raw string formatting generated on SPIFFS
    raw_log_reconstructed = "\n".join(bundle.telemetry_log) + "\n"

    # Compute HMAC-SHA256 signature using the shared secret
    computed_hmac = hmac.new(
        SHARED_SECRET, raw_log_reconstructed.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # Constant-time comparison to prevent timing side-channel attacks
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

    return {
        "status": "AUTHENTICATED_AND_VERIFIED",
        "pilot_id": bundle.pilot_id,
        "records_logged": bundle.total_entries,
        "hmac_match": True,
        "signature": computed_hmac,
    }