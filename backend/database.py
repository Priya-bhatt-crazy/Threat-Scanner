import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./sentinelx.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    type = Column(String)  # PROCESS, FILE, NETWORK, USB, AI
    severity = Column(String)  # INFO, WARNING, CRITICAL
    source = Column(String)  # e.g., "miner.exe", "invoice.pdf.exe"
    message = Column(String)
    threat_score = Column(Float, nullable=True)
    explanation = Column(String, nullable=True)
    status = Column(String, default="ACTIVE")  # ACTIVE, KILLED, QUARANTINED, DISMISSED

class Setting(Base):
    __tablename__ = "settings"

    key = Column(String, primary_key=True, index=True)
    value = Column(String)

def init_db():
    Base.metadata.create_all(bind=engine)
    
    # Initialize default settings
    db = SessionLocal()
    try:
        default_settings = [
            {"key": "auto_respond", "value": "true"},
            {"key": "auto_respond_threshold", "value": "85.0"},
            {"key": "watchdog_path", "value": "./watch_folder"},  # Monitors watch_folder by default
        ]
        for s in default_settings:
            exists = db.query(Setting).filter(Setting.key == s["key"]).first()
            if not exists:
                setting = Setting(key=s["key"], value=s["value"])
                db.add(setting)
            elif s["key"] == "watchdog_path" and exists.value == ".":
                # Migrate old '.' value to './watch_folder' to prevent dev feedback loops
                exists.value = s["value"]
        db.commit()
    finally:
        db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
