"""GET /api/status — global system metrics and policy state."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import Alert, Setting, get_db
from app.monitoring import state

router = APIRouter(prefix="/api", tags=["status"])


@router.get("/status")
def get_system_status(db: Session = Depends(get_db)):
    processes = state.monitored_processes
    total_procs = len(processes)

    max_threat = 0.0
    if processes:
        max_threat = max(p["threat_score"] for p in processes)

    auto_respond = "false"
    ar_setting = db.query(Setting).filter(Setting.key == "auto_respond").first()
    if ar_setting:
        auto_respond = ar_setting.value

    alerts_count = db.query(Alert).filter(Alert.status == "ACTIVE").count()

    return {
        "max_threat_score": max_threat,
        "total_processes": total_procs,
        "total_connections": len(state.network_connections),
        "usb_connected": state.usb_connected,
        "active_alerts_count": alerts_count,
        "auto_respond": auto_respond.lower() == "true",
        "simulation_mode": state.simulation_mode,
        "simulation_type": state.simulation_type,
    }
