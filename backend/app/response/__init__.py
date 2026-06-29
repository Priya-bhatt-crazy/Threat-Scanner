"""Automated and manual threat response actions."""

from app.response.actions import kill_process, quarantine_file
from app.response.auto_response import check_and_auto_respond

__all__ = ["kill_process", "quarantine_file", "check_and_auto_respond"]
