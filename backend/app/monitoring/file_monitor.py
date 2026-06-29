"""
Filesystem monitoring via watchdog.

Watches a configured directory for create/modify/delete events and raises
alerts for suspicious double-extension and ransomware-like filenames.
"""

import datetime
import os
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.database import Alert, SessionLocal
from app.monitoring import state


class SentinelFileHandler(FileSystemEventHandler):
    """Handles watchdog filesystem events and persists suspicious file alerts."""

    def on_any_event(self, event):
        if event.is_directory:
            return

        event_time = datetime.datetime.now().strftime("%H:%M:%S")
        event_desc = (
            f"[{event_time}] {event.event_type.upper()}: "
            f"{os.path.basename(event.src_path)}"
        )

        if event.event_type == "moved":
            event_desc += f" -> {os.path.basename(event.dest_path)}"

        with state.file_change_lock:
            state.recent_file_changes_count += 1
            state.file_events_log.append(event_desc)
            if len(state.file_events_log) > 50:
                state.file_events_log.pop(0)

        filename = os.path.basename(event.src_path).lower()
        is_suspicious = False
        alert_msg = ""

        if (
            filename.endswith(".pdf.exe")
            or filename.endswith(".docx.exe")
            or filename.endswith(".xlsx.exe")
        ):
            is_suspicious = True
            alert_msg = f"Double extension file detected: {os.path.basename(event.src_path)}"
        elif (
            filename.endswith(".locked")
            or filename.endswith(".crypto")
            or filename.endswith(".crypted")
        ):
            is_suspicious = True
            alert_msg = (
                f"Potential ransomware file modification: {os.path.basename(event.src_path)}"
            )

        if is_suspicious:
            db = SessionLocal()
            try:
                alert = Alert(
                    type="FILE",
                    severity="CRITICAL",
                    source=os.path.basename(event.src_path),
                    message=alert_msg,
                    status="ACTIVE",
                )
                db.add(alert)
                db.commit()
            finally:
                db.close()


def file_monitor_thread(watch_path: str) -> None:
    """Monitors file changes in the given directory."""
    if not os.path.exists(watch_path):
        os.makedirs(watch_path, exist_ok=True)

    event_handler = SentinelFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path=watch_path, recursive=True)
    observer.start()
    print(f"File monitoring started on path: {os.path.abspath(watch_path)}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def reset_file_changes_counter() -> None:
    """Resets the file changes counter every 30 seconds to measure change rate."""
    while True:
        time.sleep(30)
        with state.file_change_lock:
            state.recent_file_changes_count = 0
