import os
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import database
import monitor
import response
from database import get_db, Alert, Setting

# Lifespan events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize SQLite Database
    database.init_db()
    
    # 2. Get watchdog watch path from database settings
    db = database.SessionLocal()
    watch_path = "."
    try:
        setting = db.query(Setting).filter(Setting.key == "watchdog_path").first()
        if setting:
            watch_path = setting.value
    finally:
        db.close()
        
    # 3. Start monitoring threads
    monitor.start_monitoring(watch_path)
    
    # 4. Start auto-response checking thread
    import threading
    import time
    def auto_response_loop():
        while True:
            time.sleep(2)
            try:
                response.check_and_auto_respond(monitor.monitored_processes)
            except Exception:
                pass
                
    threading.Thread(target=auto_response_loop, daemon=True).start()
    
    yield

app = FastAPI(
    title="SentinelX EDR API",
    description="Real-time AI Threat Detection & Response API",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for hackathon simplicity
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Endpoints
@app.get("/api/status")
def get_system_status(db: Session = Depends(get_db)):
    # Calculate global metrics
    processes = monitor.monitored_processes
    total_procs = len(processes)
    
    # Find max threat score
    max_threat = 0.0
    if processes:
        max_threat = max(p["threat_score"] for p in processes)
        
    # Settings
    auto_respond = "false"
    ar_setting = db.query(Setting).filter(Setting.key == "auto_respond").first()
    if ar_setting:
        auto_respond = ar_setting.value
        
    # Active alerts count
    alerts_count = db.query(Alert).filter(Alert.status == "ACTIVE").count()
    
    return {
        "max_threat_score": max_threat,
        "total_processes": total_procs,
        "total_connections": len(monitor.network_connections),
        "usb_connected": monitor.usb_connected,
        "active_alerts_count": alerts_count,
        "auto_respond": auto_respond.lower() == "true",
        "simulation_mode": monitor.simulation_mode,
        "simulation_type": monitor.simulation_type
    }

@app.get("/api/processes")
def get_processes():
    return monitor.monitored_processes

@app.get("/api/network")
def get_network_connections():
    # Return connections, join with process name if available
    connections = []
    process_map = {p["pid"]: p["name"] for p in monitor.monitored_processes}
    
    for conn in monitor.network_connections:
        connections.append({
            "pid": conn["pid"],
            "name": process_map.get(conn["pid"], "Unknown Process"),
            "laddr": conn["laddr"],
            "raddr": conn["raddr"],
            "status": conn["status"],
            "type": conn["type"]
        })
    return connections

@app.get("/api/alerts")
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(50).all()
    return alerts

@app.post("/api/alerts/clear")
def clear_alerts(db: Session = Depends(get_db)):
    db.query(Alert).delete()
    db.commit()
    return {"message": "All alerts cleared."}

@app.post("/api/alerts/{alert_id}/dismiss")
def dismiss_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "DISMISSED"
    db.commit()
    return {"message": f"Alert {alert_id} dismissed."}

@app.get("/api/file-logs")
def get_file_logs():
    return monitor.file_events_log

@app.get("/api/settings")
def get_settings(db: Session = Depends(get_db)):
    settings = db.query(Setting).all()
    return {s.key: s.value for s in settings}

@app.post("/api/settings")
def update_settings(settings: dict = Body(...), db: Session = Depends(get_db)):
    for key, val in settings.items():
        setting = db.query(Setting).filter(Setting.key == key).first()
        if setting:
            setting.value = str(val)
        else:
            db.add(Setting(key=key, value=str(val)))
    db.commit()
    return {"message": "Settings updated."}

@app.post("/api/simulate")
def toggle_simulation(payload: dict = Body(...)):
    sim_type = payload.get("type", "none")  # "none", "miner", "ransomware"
    
    if sim_type not in ["none", "miner", "ransomware"]:
        raise HTTPException(status_code=400, detail="Invalid simulation type")
        
    monitor.simulation_mode = (sim_type != "none")
    monitor.simulation_type = sim_type
    
    # Reset some simulation state
    if sim_type == "none":
        # Clear any mock critical alerts to reset UI nicely
        db = database.SessionLocal()
        try:
            db.query(Alert).filter(Alert.source.in_(["xmrig_miner.exe", "wanacry_encryptor.exe"])).delete()
            db.commit()
        finally:
            db.close()
            
    return {
        "simulation_mode": monitor.simulation_mode,
        "simulation_type": monitor.simulation_type,
        "message": f"Simulation set to: {sim_type}"
    }

@app.post("/api/kill/{pid}")
def kill_process_endpoint(pid: int):
    # If it's a simulated process, just remove it from simulation
    if monitor.simulation_mode and pid in [9999, 8888]:
        monitor.simulation_mode = False
        monitor.simulation_type = "none"
        
        # Log manual termination
        db = database.SessionLocal()
        try:
            alert = Alert(
                type="PROCESS",
                severity="INFO",
                source="Simulated Process",
                message=f"Simulated process (PID {pid}) terminated by analyst response.",
                status="KILLED"
            )
            db.add(alert)
            db.commit()
        finally:
            db.close()
        return {"status": "success", "message": f"Simulated process {pid} killed."}
        
    success = response.kill_process(pid)
    if not success:
        raise HTTPException(status_code=400, detail=f"Failed to terminate process PID {pid}")
    return {"status": "success", "message": f"Process {pid} terminated."}

@app.post("/api/quarantine")
def quarantine_file_endpoint(payload: dict = Body(...)):
    filepath = payload.get("filepath", "")
    if not filepath:
        raise HTTPException(status_code=400, detail="filepath is required")
        
    destination = response.quarantine_file(filepath)
    if not destination:
        raise HTTPException(status_code=400, detail=f"Failed to quarantine file: {filepath}")
        
    return {"status": "success", "message": f"File quarantined to {destination}"}
import hashlib

# Mock database of known malware hashes (MD5 or SHA256)
MALWARE_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Test.Malware.Signature (Zero Byte Mock)",
    "5e8837cd006820f303791e84c4f507b3b12354a654817e24b480773c091911d9": "Trojan.Generic.CryptoMiner",
    "cf27db95f70b7c3d11b23a7894a4c6c06ebc60e5757d598687747e9231f82d1b": "Ransomware.WannaCry.Shadow",
}

@app.post("/api/scan-file")
def scan_file(payload: dict = Body(...), db: Session = Depends(get_db)):
    filepath = payload.get("filepath", "")
    if not filepath or not os.path.exists(filepath):
        raise HTTPException(status_code=400, detail="File path does not exist or is invalid.")
        
    try:
        # Compute SHA256 Hash
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()
        
        # Check signature matches
        is_infected = False
        threat_type = "None"
        matched_rule = "None"
        
        # 1. Check Hash Database
        if file_hash in MALWARE_HASHES:
            is_infected = True
            threat_type = MALWARE_HASHES[file_hash]
            matched_rule = f"Signature Match: Known Malware Hash [{file_hash[:12]}...]"
            
        # 2. Check Static String Signatures (Heuristics)
        if not is_infected:
            try:
                # Read first 10KB of file for text analysis
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(10240)
                    
                    suspicious_indicators = {
                        "powershell.exe -nop -w hidden": "Obfuscated PowerShell Script",
                        "eval(base64_decode": "Encoded PHP Backdoor Shell",
                        "os.system(": "System Execution Wrapper",
                        "subprocess.Popen": "Shell Process Spawner",
                        "WScript.Shell": "ActiveX Scripting Host Trojan",
                    }
                    
                    for indicator, details in suspicious_indicators.items():
                        if indicator in content:
                            is_infected = True
                            threat_type = f"Trojan.Heuristic.{details.replace(' ', '')}"
                            matched_rule = f"Pattern Match: Found suspicious instruction '{indicator}'"
                            break
            except Exception:
                pass
                
        # 3. Create database alert if infected
        if is_infected:
            alert = Alert(
                type="FILE",
                severity="CRITICAL",
                source=os.path.basename(filepath),
                message=f"Static scanner flagged {os.path.basename(filepath)} as {threat_type}. {matched_rule}",
                status="ACTIVE"
            )
            db.add(alert)
            db.commit()
                
        return {
            "filename": os.path.basename(filepath),
            "filepath": os.path.abspath(filepath),
            "size_kb": round(os.path.getsize(filepath) / 1024, 2),
            "sha256": file_hash,
            "status": "INFECTED" if is_infected else "CLEAN",
            "threat_type": threat_type,
            "details": matched_rule if is_infected else "No malicious signatures or patterns detected."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")


if __name__ == "__main__":
    import os
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, reload_dirs=[os.path.dirname(__file__)])
