"""
USB removable storage detection.

Polls disk partitions and raises alerts when removable drives are inserted or removed.
"""

import time

import psutil

from app.database import Alert, SessionLocal
from app.monitoring import state


def usb_monitor_thread() -> None:
    """Detects USB inserts/removals by polling logical drives."""
    db = SessionLocal()
    try:
        initial_drives = set(psutil.disk_partitions())
    finally:
        db.close()

    print("USB monitoring started.")

    while True:
        time.sleep(2)
        try:
            current_drives = set(psutil.disk_partitions())
            new_drives = current_drives - initial_drives
            removed_drives = initial_drives - current_drives

            if new_drives:
                for drive in new_drives:
                    if (
                        "removable" in drive.opts
                        or "cdrom" in drive.opts
                        or drive.fstype == ""
                    ):
                        state.usb_connected = True
                        db = SessionLocal()
                        try:
                            alert = Alert(
                                type="USB",
                                severity="WARNING",
                                source=drive.device,
                                message=f"New USB storage drive detected at {drive.mountpoint}",
                                status="ACTIVE",
                            )
                            db.add(alert)
                            db.commit()
                        finally:
                            db.close()

            if removed_drives:
                for drive in removed_drives:
                    state.usb_connected = False
                    db = SessionLocal()
                    try:
                        alert = Alert(
                            type="USB",
                            severity="INFO",
                            source=drive.device,
                            message=f"USB drive removed from {drive.mountpoint}",
                            status="ACTIVE",
                        )
                        db.add(alert)
                        db.commit()
                    finally:
                        db.close()

            initial_drives = current_drives
        except Exception:
            # Prevent crashes if reading drive stats raises permission error
            pass
