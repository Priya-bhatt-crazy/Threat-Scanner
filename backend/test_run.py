import requests
import sys

try:
    res = requests.get("http://127.0.0.1:8000/api/status")
    print(f"Backend is running: {res.status_code}")
    print(res.json())
except Exception as e:
    print(f"Backend is NOT running: {e}")
    sys.exit(1)
