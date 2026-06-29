"""
Monitoring thread orchestrator.

Spawns and starts all background daemon threads on application startup.
"""

import threading

from app.monitoring.file_monitor import file_monitor_thread, reset_file_changes_counter
from app.monitoring.process_monitor import process_and_network_monitor_thread
from app.monitoring.usb_monitor import usb_monitor_thread


def start_monitoring(watch_path: str) -> None:
    """Spawns all monitoring background threads."""
    t1 = threading.Thread(target=file_monitor_thread, args=(watch_path,), daemon=True)
    t2 = threading.Thread(target=reset_file_changes_counter, daemon=True)
    t3 = threading.Thread(target=usb_monitor_thread, daemon=True)
    t4 = threading.Thread(target=process_and_network_monitor_thread, daemon=True)

    t1.start()
    t2.start()
    t3.start()
    t4.start()
