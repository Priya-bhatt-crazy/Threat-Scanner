"""
Automatic Threat Response Engine
"""

from app.database import Alert, SessionLocal, Setting
from app.response.actions import kill_process

# Critical Windows processes that should never be terminated
PROTECTED_PROCESSES = {
    "system",
    "system idle process",
    "wininit.exe",
    "winlogon.exe",
    "csrss.exe",
    "services.exe",
    "lsass.exe",
    "smss.exe",
    "explorer.exe",
}


def check_and_auto_respond(monitored_processes_list):
    """
    Automatically terminates processes whose threat score exceeds
    the configured threshold.
    """

    db = SessionLocal()

    try:

        auto_respond_setting = (
            db.query(Setting)
            .filter(Setting.key == "auto_respond")
            .first()
        )

        threshold_setting = (
            db.query(Setting)
            .filter(Setting.key == "auto_respond_threshold")
            .first()
        )

        if (
            not auto_respond_setting
            or auto_respond_setting.value.lower() != "true"
        ):
            return

        threshold = (
            float(threshold_setting.value)
            if threshold_setting
            else 85.0
        )

        for proc in monitored_processes_list:

            pid = proc["pid"]
            name = proc["name"]

            # Never terminate protected Windows processes
            if name.lower() in PROTECTED_PROCESSES:
                continue

            if proc["threat_score"] < threshold:
                continue

            already_killed = (
                db.query(Alert)
                .filter(
                    Alert.type == "PROCESS",
                    Alert.message.contains(f"PID {pid}"),
                    Alert.status == "KILLED",
                )
                .first()
            )

            if already_killed:
                continue

            alert = Alert(
                type="AI",
                severity="CRITICAL",
                source=name,
                message=(
                    f"Automatic response triggered for "
                    f"{name} (PID {pid})"
                ),
                threat_score=proc["threat_score"],
                explanation=proc["explanation"],
                status="ACTIVE",
            )

            db.add(alert)
            db.commit()

            # Kill Process
            kill_process(pid)

            # Mark Alert
            alert.status = "KILLED"
            db.commit()

            print("\n" + "=" * 60)
            print("🚨 THREAT DETECTED")
            print("=" * 60)
            print(f"Process      : {name}")
            print(f"PID          : {pid}")
            print(f"Threat Score : {proc['threat_score']}%")
            print(f"Reason       : {proc['explanation']}")
            print("Action       : Process Terminated")
            print("=" * 60 + "\n")

    except Exception as e:
        print(f"[AUTO RESPONSE ERROR] {e}")

    finally:
        db.close()