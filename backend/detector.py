"""
Backward-compatibility shim.

Legacy code may `from detector import predict_threat`.
"""

from app.detection.threat_detector import predict_threat

__all__ = ["predict_threat"]
