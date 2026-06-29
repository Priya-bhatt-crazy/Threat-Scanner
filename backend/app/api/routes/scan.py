"""POST /api/scan-file — static signature file scanner."""

import os

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.scan_service import scan_file_on_disk

router = APIRouter(prefix="/api", tags=["scan"])


@router.post("/scan-file")
def scan_file(payload: dict = Body(...), db: Session = Depends(get_db)):
    filepath = payload.get("filepath", "")
    if not filepath or not os.path.exists(filepath):
        raise HTTPException(status_code=400, detail="File path does not exist or is invalid.")

    try:
        return scan_file_on_disk(filepath, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")
