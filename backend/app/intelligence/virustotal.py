"""
VirusTotal Threat Intelligence Module
"""

import hashlib
import os
import requests

# Replace with your own VirusTotal API Key
API_KEY = "8bbf814586cba26a070972f2484cec999861a3ae7dd7b0b65ff73127aba11280"

VT_URL = "https://www.virustotal.com/api/v3/files/"


def calculate_sha256(file_path: str):
    """
    Calculate SHA256 hash of a file.
    """
    if not os.path.exists(file_path):
        return None

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)

        return sha256.hexdigest()

    except Exception as e:
        print(f"[VirusTotal] Hash Error: {e}")
        return None


def scan_hash(hash_value):
    """
    Query VirusTotal using SHA256 hash.
    """

    if not hash_value:
        return None

    headers = {
        "x-apikey": API_KEY
    }

    try:

        response = requests.get(
            VT_URL + hash_value,
            headers=headers,
            timeout=10,
        )

        if response.status_code == 200:

            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }

        elif response.status_code == 404:

            return {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
            }

        else:

            print(f"[VirusTotal] HTTP {response.status_code}")

    except Exception as e:

        print(f"[VirusTotal] API Error: {e}")

    return None


def get_threat_score(vt_result):
    """
    Convert VirusTotal result into a threat score.
    """

    if not vt_result:
        return 0

    malicious = vt_result["malicious"]
    suspicious = vt_result["suspicious"]

    score = malicious * 10 + suspicious * 5

    return min(score, 35)


if __name__ == "__main__":

    path = input("Enter file path: ")

    sha = calculate_sha256(path)

    print("SHA256 :", sha)

    result = scan_hash(sha)

    print(result)

    print("Threat Score :", get_threat_score(result))