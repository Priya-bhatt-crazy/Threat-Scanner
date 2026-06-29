"""
Static file scanning service.

Encapsulates hash computation, signature matching, heuristic analysis,
and alert creation — extracted from the original main.py scan endpoint.
"""

import hashlib
import os

from sqlalchemy.orm import Session

from app.database import Alert
from app.intelligence.signatures import MALWARE_HASHES, SUSPICIOUS_INDICATORS


def scan_file_on_disk(filepath: str, db: Session) -> dict:
    """
    Scan a file on disk for known malware hashes and suspicious string patterns.

    Returns the same response dict shape as the original /api/scan-file endpoint.
    """
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    is_infected = False
    threat_type = "None"
    matched_rule = "None"

    # 1. Check hash database
    if file_hash in MALWARE_HASHES:
        is_infected = True
        threat_type = MALWARE_HASHES[file_hash]
        matched_rule = f"Signature Match: Known Malware Hash [{file_hash[:12]}...]"

    # 2. Check static string signatures (heuristics)
    if not is_infected:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(10240)

                for indicator, details in SUSPICIOUS_INDICATORS.items():
                    if indicator in content:
                        is_infected = True
                        threat_type = f"Trojan.Heuristic.{details.replace(' ', '')}"
                        matched_rule = (
                            f"Pattern Match: Found suspicious instruction '{indicator}'"
                        )
                        break
        except Exception:
            pass

    # 3. Create database alert if infected
    if is_infected:
        alert = Alert(
            type="FILE",
            severity="CRITICAL",
            source=os.path.basename(filepath),
            message=(
                f"Static scanner flagged {os.path.basename(filepath)} as {threat_type}. "
                f"{matched_rule}"
            ),
            status="ACTIVE",
        )
        db.add(alert)
        db.commit()

    return {
        "filename": os.path.basename(filepath),
        "filepath": os.path.abspath(filepath),
        "size_kb": round(os.path.getsize(filepath) / 1024, 2),
        "sha256": file_hash,
        "status": "INFECTED" if is_infected else "CLEAN",
        "threat_type": threat_type,
        "details": matched_rule if is_infected else "No malicious signatures or patterns detected.",
    }
