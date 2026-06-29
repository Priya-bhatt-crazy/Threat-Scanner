"""Alert management endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import Alert, get_db

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(50).all()
    return alerts


@router.post("/alerts/clear")
def clear_alerts(db: Session = Depends(get_db)):
    db.query(Alert).delete()
    db.commit()
    return {"message": "All alerts cleared."}


@router.post("/alerts/{alert_id}/dismiss")
def dismiss_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "DISMISSED"
    db.commit()
    return {"message": f"Alert {alert_id} dismissed."}
