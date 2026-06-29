"""POST /api/simulate — hackathon demo threat simulation."""

from fastapi import APIRouter, Body, HTTPException

from app.database import Alert, SessionLocal
from app.monitoring import state

router = APIRouter(prefix="/api", tags=["simulate"])


@router.post("/simulate")
def toggle_simulation(payload: dict = Body(...)):
    sim_type = payload.get("type", "none")

    if sim_type not in ["none", "miner", "ransomware"]:
        raise HTTPException(status_code=400, detail="Invalid simulation type")

    state.simulation_mode = sim_type != "none"
    state.simulation_type = sim_type

    if sim_type == "none":
        db = SessionLocal()
        try:
            db.query(Alert).filter(
                Alert.source.in_(["xmrig_miner.exe", "wanacry_encryptor.exe"])
            ).delete()
            db.commit()
        finally:
            db.close()

    return {
        "simulation_mode": state.simulation_mode,
        "simulation_type": state.simulation_type,
        "message": f"Simulation set to: {sim_type}",
    }
