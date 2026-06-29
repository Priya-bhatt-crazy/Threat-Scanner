"""GET /api/file-logs — watchdog filesystem event history."""

from fastapi import APIRouter

from app.monitoring import state

router = APIRouter(prefix="/api", tags=["file-logs"])


@router.get("/file-logs")
def get_file_logs():
    return state.file_events_log
