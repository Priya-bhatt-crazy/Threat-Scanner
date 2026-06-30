import requests

try:
    res = requests.post("http://127.0.0.1:8000/api/correlation/validate")
    print("API Validation Result Status:", res.status_code)
    data = res.json()
    print("Precision:", data.get("precision"))
    print("Recall:", data.get("recall"))
    print("F1-Score:", data.get("f1_score"))
    print("Confusion Matrix:", data.get("confusion_matrix"))
except Exception as e:
    print("Error calling validation API:", e)
