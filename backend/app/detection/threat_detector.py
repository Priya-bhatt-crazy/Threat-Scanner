"""
Heuristic threat scoring engine (Explainable AI).
"""

import math


def predict_threat(
    cpu_usage: float,
    memory_mb: float,
    num_connections: int,
    file_changes: int,
    usb_active: int,
    virustotal_score: int = 0,
    behavior_bonus: int = 0,
):
    """
    Predicts a threat score (0-100) and returns an explanation.
    """

    # -----------------------------
    # Feature Contributions
    # -----------------------------
    cpu_contribution = 0.0
    mem_contribution = 0.0
    conn_contribution = 0.0
    file_contribution = 0.0
    usb_contribution = 0.0
    vt_contribution = 0.0

    if cpu_usage > 80:
        cpu_contribution = 35
    elif cpu_usage > 50:
        cpu_contribution = 15

    if memory_mb > 1200:
        mem_contribution = 15
    elif memory_mb > 800:
        mem_contribution = 8

    if num_connections > 20:
        conn_contribution = 30
    elif num_connections > 10:
        conn_contribution = 15

    if file_changes > 15:
        file_contribution = 45
    elif file_changes > 8:
        file_contribution = 25

    if usb_active:
        if file_changes > 5:
            usb_contribution = 40
        elif num_connections > 8:
            usb_contribution = 30
        else:
            usb_contribution = 10

    # VirusTotal Bonus
    if virustotal_score > 0:
        vt_contribution = 35

    # -----------------------------
    # Calculate Score
    # -----------------------------
    raw_score = (
        cpu_contribution
        + mem_contribution
        + conn_contribution
        + file_contribution
        + usb_contribution
        + vt_contribution
        + behavior_bonus
    )

    if raw_score == 0:
        threat_score = 2 + (cpu_usage / 10) + (num_connections * 0.5)
    else:
        threat_score = 100 / (1 + math.exp(-0.08 * (raw_score - 40)))

    threat_score = round(min(max(threat_score, 0), 100), 1)

    # -----------------------------
    # Explainable AI
    # -----------------------------
    explanations = []

    if cpu_usage > 75:
        explanations.append(f"High CPU Usage ({cpu_usage:.1f}%)")

    if memory_mb > 800:
        explanations.append(f"High Memory Usage ({memory_mb:.1f} MB)")

    if num_connections > 12:
        explanations.append(
            f"Suspicious Network Connections ({num_connections})"
        )

    if file_changes > 8:
        explanations.append(
            f"Rapid File Changes ({file_changes})"
        )

    if usb_active:
        explanations.append(
            "USB Activity Detected"
        )

    if virustotal_score > 0:
        explanations.append(
            f"VirusTotal flagged file ({virustotal_score} engines)"
        )

    if behavior_bonus > 0:
        explanations.append(
            "Suspicious System Process Behavior"
        )

    if not explanations:
        explanations.append(
            "System operating normally."
        )

    return {
        "threat_score": threat_score,
        "explanation": " | ".join(explanations),
    }


if __name__ == "__main__":
    result = predict_threat(
        cpu_usage=90,
        memory_mb=1300,
        num_connections=22,
        file_changes=15,
        usb_active=1,
        virustotal_score=8,
        behavior_bonus=20,
    )

    print(result)