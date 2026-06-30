"""
FastAPI lifespan handler.

Bootstraps the SQLite database, starts background monitoring threads,
and launches the auto-response evaluation loop — identical startup sequence
to the original monolithic main.py.
"""

import threading
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.database import SessionLocal, Setting, init_db
from app.monitoring import start_monitoring
from app.monitoring.state import monitored_processes
from app.response.auto_response import check_and_auto_respond
from app.detection.correlation_engine import global_correlation_engine



def _auto_response_loop() -> None:
    """Background daemon that evaluates threats every 2 seconds."""
    while True:
        time.sleep(2)
        try:
            check_and_auto_respond(monitored_processes)
        except Exception:
            # Preserved from original: swallow errors to keep the loop alive
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Train AI correlation engine
    global_correlation_engine.train_model()

    # 1. Initialize SQLite database and default settings
    init_db()

    # 2. Resolve watchdog watch path from persisted settings
    db = SessionLocal()
    watch_path = "."
    try:
        setting = db.query(Setting).filter(Setting.key == "watchdog_path").first()
        if setting:
            watch_path = setting.value
    finally:
        db.close()

    # 3. Start all monitoring background threads
    start_monitoring(watch_path)

    # 4. Start auto-response checking thread
    threading.Thread(target=_auto_response_loop, daemon=True).start()

    yield
