"""
Demo threat simulation data injection.

Injects mock miner/ransomware processes into live telemetry for hackathon demos.
"""

from app.monitoring import state


def inject_simulation_data(processes_list, connections_map):
    """Simulates active threats for demonstration purposes."""
    if state.simulation_type == "miner":
        miner_proc = {
            "pid": 9999,
            "name": "xmrig_miner.exe",
            "cpu": 92.4,
            "memory": 720.0,
            "connections": 14,
            "parent_id": 4500,
            "exe": "C:\\Users\\User\\Downloads\\xmrig_miner.exe",
            "threat_score": 88.5,
            "explanation": (
                "Abnormally high CPU utilization (92.4%) | "
                "Suspicious number of network connections (14 active)"
            ),
        }
        processes_list.insert(0, miner_proc)

        state.network_connections.append(
            {
                "pid": 9999,
                "laddr": "192.168.1.15:52134",
                "raddr": "139.99.125.109:443",
                "status": "ESTABLISHED",
                "type": "SOCK_STREAM",
            }
        )

    elif state.simulation_type == "ransomware":
        ransom_proc = {
            "pid": 8888,
            "name": "wanacry_encryptor.exe",
            "cpu": 34.1,
            "memory": 180.0,
            "connections": 4,
            "parent_id": 4500,
            "exe": "C:\\Users\\User\\AppData\\Local\\Temp\\wanacry_encryptor.exe",
            "threat_score": 94.2,
            "explanation": (
                "Rapid directory modifications (45 file edits detected) | "
                "Active process associated with USB mass storage insertion"
                if state.usb_connected
                else "Rapid directory modifications (45 file edits detected)"
            ),
        }
        processes_list.insert(0, ransom_proc)
        state.recent_file_changes_count = 35
