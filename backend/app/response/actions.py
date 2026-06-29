"""
Manual response actions: process termination and file quarantine.

Moved from the original response.py module.
"""

import datetime
import os
import shutil

import psutil

from app.core.config import QUARANTINE_DIR
from app.database import Alert, SessionLocal


def kill_process(pid: int) -> bool:
    """Terminates a process by its PID."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.terminate()

        db = SessionLocal()
        try:
            alert = Alert(
                type="PROCESS",
                severity="INFO",
                source=name,
                message=f"Process {name} (PID {pid}) terminated successfully.",
                status="KILLED",
            )
            db.add(alert)
            db.commit()
        finally:
            db.close()
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        db = SessionLocal()
        try:
            alert = Alert(
                type="PROCESS",
                severity="WARNING",
                source=str(pid),
                message=f"Failed to terminate process PID {pid}: Access Denied or process closed.",
                status="ACTIVE",
            )
            db.add(alert)
            db.commit()
        finally:
            db.close()
        return False


def quarantine_file(filepath: str) -> str:
    """Moves a file to the quarantine directory."""
    if not os.path.exists(filepath):
        return ""

    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

    filename = os.path.basename(filepath)
    destination = os.path.join(QUARANTINE_DIR, filename)

    # Avoid overwriting
    if os.path.exists(destination):
        base, ext = os.path.splitext(filename)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        destination = os.path.join(QUARANTINE_DIR, f"{base}_{timestamp}{ext}")

    try:
        shutil.move(filepath, destination)

        db = SessionLocal()
        try:
            alert = Alert(
                type="FILE",
                severity="INFO",
                source=filename,
                message=f"File quarantined: Moved from {filepath} to {destination}",
                status="QUARANTINED",
            )
            db.add(alert)
            db.commit()
        finally:
            db.close()
        return destination
    except Exception as e:
        db = SessionLocal()
        try:
            alert = Alert(
                type="FILE",
                severity="WARNING",
                source=filename,
                message=f"Failed to quarantine file {filename}: {str(e)}",
                status="ACTIVE",
            )
            db.add(alert)
            db.commit()
        finally:
            db.close()
        return ""
