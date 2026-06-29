"""
Filesystem Monitoring using Watchdog.
Monitors file creations/modifications and detects:
- Double Extension Files
- Ransomware Extensions
- VirusTotal Known Malware
"""

import datetime
import os
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.database import Alert, SessionLocal
from app.monitoring import state
from app.intelligence.virustotal import (
    calculate_sha256,
    scan_hash,
)


class SentinelFileHandler(FileSystemEventHandler):

    def on_any_event(self, event):
        print(f"[WATCHDOG] {event.event_type}: {event.src_path}")

        if event.is_directory:
            return

        filename = os.path.basename(event.src_path).lower()

        print(f"[WATCHDOG] {event.event_type.upper()} -> {filename}")

        event_time = datetime.datetime.now().strftime("%H:%M:%S")

        event_desc = (
            f"[{event_time}] "
            f"{event.event_type.upper()}: {filename}"
        )

        with state.file_change_lock:

            state.recent_file_changes_count += 1

            state.file_events_log.append(event_desc)

            if len(state.file_events_log) > 50:
                state.file_events_log.pop(0)

        is_suspicious = False
        alert_msg = ""

        # --------------------------------------------------
        # VirusTotal Scan
        # --------------------------------------------------

        try:

            if os.path.exists(event.src_path):

                sha256 = calculate_sha256(event.src_path)

                vt_result = scan_hash(sha256)

                if vt_result:

                    malicious = vt_result.get("malicious", 0)

                    if malicious > 0:

                        is_suspicious = True

                        alert_msg = (
                            f"VirusTotal detected malware "
                            f"({malicious} engines)"
                        )

        except Exception as e:

            print("[VirusTotal Error]", e)

        # --------------------------------------------------
        # Double Extension Detection
        # --------------------------------------------------

        if (
            filename.endswith(".pdf.exe")
            or filename.endswith(".docx.exe")
            or filename.endswith(".xlsx.exe")
        ):

            print("[ALERT] Double Extension")

            is_suspicious = True

            alert_msg = (
                f"Double extension detected: {filename}"
            )

        # --------------------------------------------------
        # Ransomware Detection
        # --------------------------------------------------

        elif (
            filename.endswith(".locked")
            or filename.endswith(".crypto")
            or filename.endswith(".crypted")
        ):

            print("[ALERT] Ransomware")

            is_suspicious = True

            alert_msg = (
                f"Possible ransomware activity: {filename}"
            )

        # --------------------------------------------------
        # Save Alert
        # --------------------------------------------------

        if is_suspicious:

            print("[DATABASE] Saving Alert")

            db = SessionLocal()

            try:

                alert = Alert(
                    type="FILE",
                    severity="CRITICAL",
                    source=filename,
                    message=alert_msg,
                    status="ACTIVE",
                )

                db.add(alert)

                db.commit()

                print("[DATABASE] Alert Saved Successfully")

            except Exception as e:

                db.rollback()

                print("[DATABASE ERROR]", e)

            finally:

                db.close()


def file_monitor_thread(watch_path):

    if not os.path.exists(watch_path):
        os.makedirs(watch_path)

    observer = Observer()

    observer.schedule(
        SentinelFileHandler(),
        watch_path,
        recursive=True,
    )

    observer.start()

    print("=" * 60)
    print("FILE MONITOR STARTED")
    print("Watching :", os.path.abspath(watch_path))
    print("=" * 60)

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

    observer.join()


def reset_file_changes_counter():

    while True:

        time.sleep(30)

        with state.file_change_lock:

            state.recent_file_changes_count = 0 