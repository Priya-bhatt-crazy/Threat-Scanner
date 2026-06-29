"""POST /api/kill and POST /api/quarantine — manual response actions."""

from fastapi import APIRouter, Body, HTTPException

from app.database import Alert, SessionLocal
from app.monitoring import state
from app.response import kill_process, quarantine_file

router = APIRouter(prefix="/api", tags=["response"])


@router.post("/kill/{pid}")
def kill_process_endpoint(pid: int):
    if state.simulation_mode and pid in [9999, 8888]:
        state.simulation_mode = False
        state.simulation_type = "none"

        db = SessionLocal()
        try:
            alert = Alert(
                type="PROCESS",
                severity="INFO",
                source="Simulated Process",
                message=f"Simulated process (PID {pid}) terminated by analyst response.",
                status="KILLED",
            )
            db.add(alert)
            db.commit()
        finally:
            db.close()
        return {"status": "success", "message": f"Simulated process {pid} killed."}

    success = kill_process(pid)
    if not success:
        raise HTTPException(
            status_code=400, detail=f"Failed to terminate process PID {pid}"
        )
    return {"status": "success", "message": f"Process {pid} terminated."}


@router.post("/quarantine")
def quarantine_file_endpoint(payload: dict = Body(...)):
    filepath = payload.get("filepath", "")
    if not filepath:
        raise HTTPException(status_code=400, detail="filepath is required")

    destination = quarantine_file(filepath)
    if not destination:
        raise HTTPException(status_code=400, detail=f"Failed to quarantine file: {filepath}")

    return {"status": "success", "message": f"File quarantined to {destination}"}
