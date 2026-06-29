import time
import threading
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import datetime
from database import SessionLocal, Alert
from detector import predict_threat

# Global state to share between threads
monitored_processes = []
network_connections = []
recent_file_changes_count = 0
file_change_lock = threading.Lock()
usb_connected = False
simulation_mode = False
simulation_type = "none"  # "none", "miner", "ransomware"

# History log of file events
file_events_log = []

class SentinelFileHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        global recent_file_changes_count
        if event.is_directory:
            return
            
        event_time = datetime.datetime.now().strftime("%H:%M:%S")
        event_desc = f"[{event_time}] {event.event_type.upper()}: {os.path.basename(event.src_path)}"
        
        # Log rename details
        if event.event_type == 'moved':
            event_desc += f" -> {os.path.basename(event.dest_path)}"
            
        with file_change_lock:
            recent_file_changes_count += 1
            file_events_log.append(event_desc)
            if len(file_events_log) > 50:
                file_events_log.pop(0)
                
        # Check for suspicious file extensions (e.g., .pdf.exe or ransomware extensions)
        filename = os.path.basename(event.src_path).lower()
        is_suspicious = False
        alert_msg = ""
        
        if filename.endswith(".pdf.exe") or filename.endswith(".docx.exe") or filename.endswith(".xlsx.exe"):
            is_suspicious = True
            alert_msg = f"Double extension file detected: {os.path.basename(event.src_path)}"
        elif filename.endswith(".locked") or filename.endswith(".crypto") or filename.endswith(".crypted"):
            is_suspicious = True
            alert_msg = f"Potential ransomware file modification: {os.path.basename(event.src_path)}"
            
        if is_suspicious:
            db = SessionLocal()
            try:
                alert = Alert(
                    type="FILE",
                    severity="CRITICAL",
                    source=os.path.basename(event.src_path),
                    message=alert_msg,
                    status="ACTIVE"
                )
                db.add(alert)
                db.commit()
            finally:
                db.close()

def file_monitor_thread(watch_path):
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

def reset_file_changes_counter():
    """Resets the file changes counter every 30 seconds to get the rate."""
    global recent_file_changes_count
    while True:
        time.sleep(30)
        with file_change_lock:
            recent_file_changes_count = 0

def usb_monitor_thread():
    """Detects USB inserts/removals by polling logical drives."""
    global usb_connected
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
                    if 'removable' in drive.opts or 'cdrom' in drive.opts or drive.fstype == "":
                        usb_connected = True
                        db = SessionLocal()
                        try:
                            alert = Alert(
                                type="USB",
                                severity="WARNING",
                                source=drive.device,
                                message=f"New USB storage drive detected at {drive.mountpoint}",
                                status="ACTIVE"
                            )
                            db.add(alert)
                            db.commit()
                        finally:
                            db.close()
                            
            if removed_drives:
                for drive in removed_drives:
                    usb_connected = False
                    db = SessionLocal()
                    try:
                        alert = Alert(
                            type="USB",
                            severity="INFO",
                            source=drive.device,
                            message=f"USB drive removed from {drive.mountpoint}",
                            status="ACTIVE"
                        )
                        db.add(alert)
                        db.commit()
                    finally:
                        db.close()
                        
            initial_drives = current_drives
        except Exception as e:
            # Prevent crashes if reading drive stats raises permission error
            pass

def process_and_network_monitor_thread():
    """Collects active processes and network connections and evaluates their threat score."""
    global monitored_processes, network_connections
    print("Process and network monitoring started.")
    
    while True:
        try:
            # 1. Network Connections mapping
            connections_map = {}
            raw_connections = []
            try:
                for conn in psutil.net_connections(kind='inet'):
                    pid = conn.pid
                    if pid:
                        # Count active connections per PID
                        connections_map[pid] = connections_map.get(pid, 0) + 1
                        
                        # Save connection detail
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
                        raw_connections.append({
                            "pid": pid,
                            "laddr": laddr,
                            "raddr": raddr,
                            "status": conn.status,
                            "type": conn.type.name
                        })
            except Exception:
                # Fallback if net_connections requires admin permissions on this machine
                pass
                
            network_connections = raw_connections
            
            # 2. Get processes and evaluate AI threat
            procs = []
            count = 0
            
            # Limit the number of processes we scan to avoid CPU lag during demo
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'ppid', 'exe']):
                try:
                    pinfo = proc.info
                    pid = pinfo.get('pid')
                    name = pinfo.get('name')
                    
                    # Skip invalid/inaccessible processes
                    if not pid or isinstance(pid, Exception) or not name or isinstance(name, Exception):
                        continue
                    
                    # Exclude idle process and system stuff from heavy AI checks
                    if pid == 0 or name in ["System Idle Process", "System"]:
                        continue
                        
                    cpu = pinfo.get('cpu_percent')
                    if isinstance(cpu, Exception) or cpu is None:
                        cpu = 0.0
                        
                    mem_info = pinfo.get('memory_info')
                    if isinstance(mem_info, Exception) or mem_info is None:
                        mem = 0.0
                    else:
                        try:
                            mem = mem_info.rss / (1024 * 1024) # MB
                        except Exception:
                            mem = 0.0
                        
                    parent_id = pinfo.get('ppid')
                    if isinstance(parent_id, Exception) or parent_id is None:
                        parent_id = 0
                        
                    exe = pinfo.get('exe')
                    if isinstance(exe, Exception) or exe is None:
                        exe = "Access Denied"
                    
                    # Fetch connection count
                    conns_count = connections_map.get(pid, 0)
                    
                    # Call Threat Detector
                    file_changes = recent_file_changes_count
                    usb_active = 1 if usb_connected else 0
                    
                    threat_data = predict_threat(
                        cpu_usage=cpu,
                        memory_mb=mem,
                        num_connections=conns_count,
                        file_changes=file_changes,
                        usb_active=usb_active
                    )
                    
                    procs.append({
                        "pid": pid,
                        "name": name,
                        "cpu": round(cpu, 1),
                        "memory": round(mem, 1),
                        "connections": conns_count,
                        "parent_id": parent_id,
                        "exe": exe,
                        "threat_score": threat_data["threat_score"],
                        "explanation": threat_data["explanation"]
                    })
                    
                    count += 1
                    if count > 80:  # Cap list size
                        break
                except Exception:
                    continue
            
            # 3. Handle Simulations
            if simulation_mode:
                inject_simulation_data(procs, connections_map)
                
            # Sort processes by threat score descending
            procs.sort(key=lambda x: x["threat_score"], reverse=True)
            monitored_processes = procs
            
        except Exception as e:
            print(f"Error in process monitor thread: {e}")
            
        time.sleep(2)

def inject_simulation_data(processes_list, connections_map):
    """Simulates active threats for demonstration purposes."""
    global simulation_type, usb_connected
    
    if simulation_type == "miner":
        # Simulate cryptominer spike
        miner_proc = {
            "pid": 9999,
            "name": "xmrig_miner.exe",
            "cpu": 92.4,
            "memory": 720.0,
            "connections": 14,
            "parent_id": 4500,
            "exe": "C:\\Users\\User\\Downloads\\xmrig_miner.exe",
            "threat_score": 88.5,
            "explanation": "Abnormally high CPU utilization (92.4%) | Suspicious number of network connections (14 active)"
        }
        # Add to processes
        processes_list.insert(0, miner_proc)
        
        # Inject network connections
        network_connections.append({
            "pid": 9999,
            "laddr": "192.168.1.15:52134",
            "raddr": "139.99.125.109:443", # Mock pool
            "status": "ESTABLISHED",
            "type": "SOCK_STREAM"
        })
        
    elif simulation_type == "ransomware":
        # Simulate ransomware file locking storm
        ransom_proc = {
            "pid": 8888,
            "name": "wanacry_encryptor.exe",
            "cpu": 34.1,
            "memory": 180.0,
            "connections": 4,
            "parent_id": 4500,
            "exe": "C:\\Users\\User\\AppData\\Local\\Temp\\wanacry_encryptor.exe",
            "threat_score": 94.2,
            "explanation": "Rapid directory modifications (45 file edits detected) | Active process associated with USB mass storage insertion" if usb_connected else "Rapid directory modifications (45 file edits detected)"
        }
        processes_list.insert(0, ransom_proc)
        
        # Add files changes
        global recent_file_changes_count
        recent_file_changes_count = 35

def start_monitoring(watch_path):
    """Spawns all monitoring background threads."""
    t1 = threading.Thread(target=file_monitor_thread, args=(watch_path,), daemon=True)
    t2 = threading.Thread(target=reset_file_changes_counter, daemon=True)
    t3 = threading.Thread(target=usb_monitor_thread, daemon=True)
    t4 = threading.Thread(target=process_and_network_monitor_thread, daemon=True)
    
    t1.start()
    t2.start()
    t3.start()
    t4.start()
