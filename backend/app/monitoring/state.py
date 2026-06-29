"""
Shared in-memory monitoring state.

All background threads read and write these module-level variables.
Centralizing them avoids circular imports between monitor submodules.
"""

import threading

# Process and network telemetry (refreshed every 2 seconds)
monitored_processes: list = []
network_connections: list = []

# File system activity counters and log
recent_file_changes_count: int = 0
file_change_lock = threading.Lock()
file_events_log: list = []

# USB and simulation flags
usb_connected: bool = False
simulation_mode: bool = False
simulation_type: str = "none"  # "none", "miner", "ransomware"
