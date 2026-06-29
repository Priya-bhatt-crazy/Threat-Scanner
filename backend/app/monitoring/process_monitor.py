"""
Process and network connection monitoring.

Collects live endpoint telemetry via psutil and evaluates each process
with the heuristic threat detection engine.
"""

import time

import psutil

from app.detection import predict_threat
from app.monitoring import state
from app.monitoring.simulation import inject_simulation_data


def process_and_network_monitor_thread() -> None:
    """Collects active processes and network connections and evaluates threat scores."""
    print("Process and network monitoring started.")

    while True:
        try:
            connections_map = {}
            raw_connections = []
            try:
                for conn in psutil.net_connections(kind="inet"):
                    pid = conn.pid
                    if pid:
                        connections_map[pid] = connections_map.get(pid, 0) + 1

                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
                        raw_connections.append(
                            {
                                "pid": pid,
                                "laddr": laddr,
                                "raddr": raddr,
                                "status": conn.status,
                                "type": conn.type.name,
                            }
                        )
            except Exception:
                # Fallback if net_connections requires admin permissions on this machine
                pass

            # In-place update so all module re-exports share the same list object
            state.network_connections[:] = raw_connections

            procs = []
            count = 0

            for proc in psutil.process_iter(
                ["pid", "name", "cpu_percent", "memory_info", "ppid", "exe"]
            ):
                try:
                    pinfo = proc.info
                    pid = pinfo.get("pid")
                    name = pinfo.get("name")

                    if not pid or isinstance(pid, Exception) or not name or isinstance(name, Exception):
                        continue

                    if pid == 0 or name in ["System Idle Process", "System"]:
                        continue

                    cpu = pinfo.get("cpu_percent")
                    if isinstance(cpu, Exception) or cpu is None:
                        cpu = 0.0

                    mem_info = pinfo.get("memory_info")
                    if isinstance(mem_info, Exception) or mem_info is None:
                        mem = 0.0
                    else:
                        try:
                            mem = mem_info.rss / (1024 * 1024)
                        except Exception:
                            mem = 0.0

                    parent_id = pinfo.get("ppid")
                    if isinstance(parent_id, Exception) or parent_id is None:
                        parent_id = 0

                    exe = pinfo.get("exe")
                    if isinstance(exe, Exception) or exe is None:
                        exe = "Access Denied"

                    conns_count = connections_map.get(pid, 0)

                    file_changes = state.recent_file_changes_count
                    usb_active = 1 if state.usb_connected else 0

                    # -----------------------------
                    # Behavior Analysis
                    # -----------------------------
                    behavior_bonus = 0

                    suspicious_processes = [
                        "powershell.exe",
                        "cmd.exe",
                        "wmic.exe",
                        "mshta.exe",
                        "rundll32.exe",
                        "regsvr32.exe",
                        "certutil.exe",
                    ]

                    if name.lower() in suspicious_processes:
                        behavior_bonus += 20

                    # VirusTotal score (will come from file monitoring later)
                    virustotal_score = 0

                    threat_data = predict_threat(
                        cpu_usage=cpu,
                        memory_mb=mem,
                        num_connections=conns_count,
                        file_changes=file_changes,
                        usb_active=usb_active,
                        virustotal_score=virustotal_score,
                        behavior_bonus=behavior_bonus,
                    )

                    procs.append(
                        {
                            "pid": pid,
                            "name": name,
                            "cpu": round(cpu, 1),
                            "memory": round(mem, 1),
                            "connections": conns_count,
                            "parent_id": parent_id,
                            "exe": exe,
                            "threat_score": threat_data["threat_score"],
                            "explanation": threat_data["explanation"],
                        }
                    )

                    count += 1
                    if count > 80:
                        break
                except Exception:
                    continue

            if state.simulation_mode:
                inject_simulation_data(procs, connections_map)

            procs.sort(key=lambda x: x["threat_score"], reverse=True)
            state.monitored_processes[:] = procs

        except Exception as e:
            print(f"Error in process monitor thread: {e}")

        time.sleep(2)
