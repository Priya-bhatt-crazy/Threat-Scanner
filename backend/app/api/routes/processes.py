"""GET /api/processes and GET /api/network — live endpoint telemetry."""

from fastapi import APIRouter

from app.monitoring import state

router = APIRouter(prefix="/api", tags=["processes"])


@router.get("/processes")
def get_processes():
    return state.monitored_processes


@router.get("/network")
def get_network_connections():
    connections = []
    process_map = {p["pid"]: p["name"] for p in state.monitored_processes}

    for conn in state.network_connections:
        connections.append(
            {
                "pid": conn["pid"],
                "name": process_map.get(conn["pid"], "Unknown Process"),
                "laddr": conn["laddr"],
                "raddr": conn["raddr"],
                "status": conn["status"],
                "type": conn["type"],
            }
        )
    return connections
