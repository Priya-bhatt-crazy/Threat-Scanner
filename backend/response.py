"""
Backward-compatibility shim.

Legacy code may `import response` — action functions are re-exported from app.response.
"""

from app.core.config import QUARANTINE_DIR
from app.response.actions import kill_process, quarantine_file
from app.response.auto_response import check_and_auto_respond

__all__ = [
    "QUARANTINE_DIR",
    "kill_process",
    "quarantine_file",
    "check_and_auto_respond",
]
