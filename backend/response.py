import os
import shutil
import psutil
import datetime
from database import SessionLocal, Alert, Setting

QUARANTINE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "quarantine"))

def kill_process(pid: int) -> bool:
    """Terminates a process by its PID."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.terminate()
        
        # Log to Database
        db = SessionLocal()
        try:
            alert = Alert(
                type="PROCESS",
                severity="INFO",
                source=name,
                message=f"Process {name} (PID {pid}) terminated successfully.",
                status="KILLED"
            )
            db.add(alert)
            db.commit()
        finally:
            db.close()
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        db = SessionLocal()
        try:
            alert = Alert(
                type="PROCESS",
                severity="WARNING",
                source=str(pid),
                message=f"Failed to terminate process PID {pid}: Access Denied or process closed.",
                status="ACTIVE"
            )
            db.add(alert)
            db.commit()
        finally:
            db.close()
        return False

def quarantine_file(filepath: str) -> str:
    """Moves a file to the quarantine directory."""
    if not os.path.exists(filepath):
        return ""
        
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        
    filename = os.path.basename(filepath)
    destination = os.path.join(QUARANTINE_DIR, filename)
    
    # Avoid overwriting
    if os.path.exists(destination):
        base, ext = os.path.splitext(filename)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        destination = os.path.join(QUARANTINE_DIR, f"{base}_{timestamp}{ext}")
        
    try:
        shutil.move(filepath, destination)
        
        # Log to Database
        db = SessionLocal()
        try:
            alert = Alert(
                type="FILE",
                severity="INFO",
                source=filename,
                message=f"File quarantined: Moved from {filepath} to {destination}",
                status="QUARANTINED"
            )
            db.add(alert)
            db.commit()
        finally:
            db.close()
        return destination
    except Exception as e:
        db = SessionLocal()
        try:
            alert = Alert(
                type="FILE",
                severity="WARNING",
                source=filename,
                message=f"Failed to quarantine file {filename}: {str(e)}",
                status="ACTIVE"
            )
            db.add(alert)
            db.commit()
        finally:
            db.close()
        return ""

def check_and_auto_respond(monitored_processes_list):
    """
    Checks if auto-response is enabled and executes mitigation if a threat 
    exceeds the configured threshold.
    """
    db = SessionLocal()
    try:
        auto_respond_setting = db.query(Setting).filter(Setting.key == "auto_respond").first()
        threshold_setting = db.query(Setting).filter(Setting.key == "auto_respond_threshold").first()
        
        if not auto_respond_setting or auto_respond_setting.value.lower() != "true":
            return
            
        threshold = float(threshold_setting.value) if threshold_setting else 85.0
        
        for proc in monitored_processes_list:
            if proc["threat_score"] >= threshold:
                pid = proc["pid"]
                name = proc["name"]
                
                # Check if we already logged/killed this PID to avoid loops
                already_killed = db.query(Alert).filter(
                    Alert.type == "PROCESS",
                    Alert.message.contains(f"PID {pid}"),
                    Alert.status == "KILLED"
                ).first()
                
                if not already_killed:
                    # Log Critical Auto-Response Triggered
                    alert = Alert(
                        type="AI",
                        severity="CRITICAL",
                        source=name,
                        message=f"AI engine triggered automatic response for {name} (Threat: {proc['threat_score']}%). Terminating...",
                        threat_score=proc["threat_score"],
                        explanation=proc["explanation"],
                        status="ACTIVE"
                    )
                    db.add(alert)
                    db.commit()
                    
                    # Execute response
                    kill_process(pid)
                    print(f"[AUTO-RESPOND] Automatically terminated process {name} (PID {pid}) due to threat score {proc['threat_score']}%")
    except Exception as e:
        print(f"Error in auto-response evaluation: {e}")
    finally:
        db.close()
