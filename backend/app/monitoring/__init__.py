"""
Real-time endpoint monitoring package.

Exports shared state and the start_monitoring entry point used at app startup.
Re-exports state variables at package level for backward compatibility with
the original monitor.py import style (monitor.monitored_processes, etc.).
"""

from app.monitoring.manager import start_monitoring
from app.monitoring.state import (
    file_change_lock,
    file_events_log,
    monitored_processes,
    network_connections,
    recent_file_changes_count,
    simulation_mode,
    simulation_type,
    usb_connected,
)

__all__ = [
    "start_monitoring",
    "monitored_processes",
    "network_connections",
    "recent_file_changes_count",
    "file_change_lock",
    "usb_connected",
    "simulation_mode",
    "simulation_type",
    "file_events_log",
]
