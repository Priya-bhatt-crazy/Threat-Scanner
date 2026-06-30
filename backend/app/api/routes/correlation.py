"""
FastAPI routes for AI Attack Correlation Engine.
Endpoints for status, validation report, and live simulations.
"""

from fastapi import APIRouter, Body, HTTPException
from app.database import Alert, SessionLocal
from app.detection.correlation_engine import (
    global_correlation_engine,
    evaluate_engine_metrics,
    get_predefined_scenarios,
    AttackCorrelationEngine
)
import time

router = APIRouter(prefix="/api/correlation", tags=["correlation"])


@router.get("/status")
def get_correlation_status():
    """Returns active correlated process trees and overall system metrics."""
    # Ensure model is trained
    if not global_correlation_engine.is_trained:
        global_correlation_engine.train_model()
        
    global_correlation_engine.classify_all_trees()
    
    trees_data = []
    for pid, tree in global_correlation_engine.process_trees.items():
        trees_data.append({
            "root_pid": tree["root_pid"],
            "root_name": tree["root_name"],
            "stages": list(tree["stages"]),
            "timeline": tree["timeline"],
            "is_attack": tree["is_attack"],
            "threat_score": tree["threat_score"],
            "explanation": tree["explanation"],
            "process_count": len(tree["processes"]),
            "connection_count": len(tree["connections"]),
            "file_changes_count": len(tree["file_changes"])
        })
        
    trees_data.sort(key=lambda x: x["threat_score"], reverse=True)
    
    # Calculate global max correlated score
    max_score = max([t["threat_score"] for t in trees_data]) if trees_data else 0.0
    
    return {
        "max_correlated_score": max_score,
        "active_trees": trees_data,
        "is_trained": global_correlation_engine.is_trained
    }


@router.post("/validate")
def run_model_validation():
    """Runs the 15 scenarios, returns Precision, Recall, F1-Score, and results details."""
    try:
        metrics = evaluate_engine_metrics()
        return metrics
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")


@router.post("/simulate")
def simulate_correlation_scenario(payload: dict = Body(...)):
    """
    Simulates a scenario by running events step-by-step through a temporary engine,
    and returns a step-by-step detection timeline for live frontend demonstration.
    """
    scenario_id = payload.get("scenario_id")
    if not scenario_id:
        raise HTTPException(status_code=400, detail="Missing scenario_id")
        
    scenarios = get_predefined_scenarios()
    scenario = next((s for s in scenarios if s["id"] == scenario_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
        
    # Run step-by-step simulation
    sim_engine = AttackCorrelationEngine()
    sim_engine.clf = global_correlation_engine.clf
    sim_engine.is_trained = True
    
    steps = []
    
    for i, event in enumerate(scenario["events"]):
        # Add event to simulation engine
        sim_engine.add_event(event)
        sim_engine.classify_all_trees()
        
        # Extract status after this step
        roots = list(sim_engine.process_trees.keys())
        if roots:
            root_pid = roots[0]
            tree = sim_engine.process_trees[root_pid]
            current_stages = list(tree["stages"])
            current_timeline = list(tree["timeline"])
            is_attack = tree["is_attack"]
            threat_score = tree["threat_score"]
            explanation = tree["explanation"]
        else:
            current_stages = []
            current_timeline = []
            is_attack = False
            threat_score = 0.0
            explanation = "No process tree created"
            
        steps.append({
            "step_index": i + 1,
            "event": event,
            "current_stages": current_stages,
            "current_timeline": current_timeline,
            "is_attack": is_attack,
            "threat_score": threat_score,
            "explanation": explanation
        })
        
    # If the simulation correlates an attack, save a critical alert to the DB
    if is_attack:
        db = SessionLocal()
        try:
            # Clean up old simulation alerts of this name first to prevent spamming
            db.query(Alert).filter(Alert.source == f"SIM:{scenario['id']}").delete()
            
            alert = Alert(
                type="AI",
                severity="CRITICAL",
                source=f"SIM:{scenario['id']}",
                message=f"AI Correlation Engine Alert: Multi-stage cyber attack identified ({scenario['name']})",
                threat_score=threat_score,
                explanation=explanation,
                status="ACTIVE"
            )
            db.add(alert)
            db.commit()
        except Exception as e:
            db.rollback()
            print("[SIMULATION DB ERROR]", e)
        finally:
            db.close()
            
    return {
        "scenario_id": scenario["id"],
        "name": scenario["name"],
        "type": scenario["type"],
        "total_steps": len(scenario["events"]),
        "is_attack_correlated": is_attack,
        "final_threat_score": threat_score,
        "final_explanation": explanation,
        "steps": steps
    }
