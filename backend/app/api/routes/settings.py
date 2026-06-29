"""GET/POST /api/settings — persisted configuration."""

from fastapi import APIRouter, Body, Depends
from sqlalchemy.orm import Session

from app.database import Setting, get_db

router = APIRouter(prefix="/api", tags=["settings"])


@router.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    settings = db.query(Setting).all()
    return {s.key: s.value for s in settings}


@router.post("/settings")
def update_settings(settings: dict = Body(...), db: Session = Depends(get_db)):
    for key, val in settings.items():
        setting = db.query(Setting).filter(Setting.key == key).first()
        if setting:
            setting.value = str(val)
        else:
            db.add(Setting(key=key, value=str(val)))
    db.commit()
    return {"message": "Settings updated."}
