"""
Automatic threat response engine.

Evaluates monitored processes against the configured threshold and triggers
process termination when auto-response policy is enabled.
"""

from app.database import Alert, SessionLocal, Setting
from app.response.actions import kill_process


def check_and_auto_respond(monitored_processes_list):
    """
    Checks if auto-response is enabled and executes mitigation if a threat
    exceeds the configured threshold.
    """
    db = SessionLocal()
    try:
        auto_respond_setting = db.query(Setting).filter(Setting.key == "auto_respond").first()
        threshold_setting = db.query(Setting).filter(
            Setting.key == "auto_respond_threshold"
        ).first()

        if not auto_respond_setting or auto_respond_setting.value.lower() != "true":
            return

        threshold = float(threshold_setting.value) if threshold_setting else 85.0

        for proc in monitored_processes_list:
            if proc["threat_score"] >= threshold:
                pid = proc["pid"]
                name = proc["name"]

                # Check if we already logged/killed this PID to avoid loops
                already_killed = (
                    db.query(Alert)
                    .filter(
                        Alert.type == "PROCESS",
                        Alert.message.contains(f"PID {pid}"),
                        Alert.status == "KILLED",
                    )
                    .first()
                )

                if not already_killed:
                    alert = Alert(
                        type="AI",
                        severity="CRITICAL",
                        source=name,
                        message=(
                            f"AI engine triggered automatic response for {name} "
                            f"(Threat: {proc['threat_score']}%). Terminating..."
                        ),
                        threat_score=proc["threat_score"],
                        explanation=proc["explanation"],
                        status="ACTIVE",
                    )
                    db.add(alert)
                    db.commit()

                    kill_process(pid)
                    print(
                        f"[AUTO-RESPOND] Automatically terminated process {name} (PID {pid}) "
                        f"due to threat score {proc['threat_score']}%"
                    )
    except Exception as e:
        print(f"Error in auto-response evaluation: {e}")
    finally:
        db.close()
