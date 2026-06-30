import sqlite3
import urllib.request
import urllib.error
import json
from passlib.context import CryptContext

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)

def check_db():
    db_path = "sentinelx.db"
    print(f"--- 1. DATABASE DIAGNOSTICS ({db_path}) ---")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check tables list
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print("Tables in database:", [t[0] for t in tables])
        
        if ("users",) in tables:
            cursor.execute("SELECT id, username, password, role, is_active FROM users;")
            users = cursor.fetchall()
            print(f"Found {len(users)} users in database:")
            for u in users:
                uid, username, pwd_hash, role, active = u
                print(f"  - ID: {uid} | Username: {username} | Role: {role} | Active: {active}")
                
                # Test standard passwords
                test_pwds = ["admin123", "analyst123", "viewer123"]
                verified = None
                for p in test_pwds:
                    try:
                        if pwd_context.verify(p, pwd_hash):
                            verified = p
                            break
                    except Exception as e:
                        pass
                if verified:
                    print(f"    ✓ Password verified: '{verified}'")
                else:
                    # Check plain-text
                    if pwd_hash in test_pwds:
                        print(f"    ✓ Password stored in plain-text: '{pwd_hash}'")
                    else:
                        print("    ✕ Could not verify password with standard credentials.")
        else:
            print("ERROR: 'users' table does not exist!")
            
        conn.close()
    except Exception as e:
        print(f"Database read error: {e}")

def check_network_endpoint(url):
    print(f"\n--- Testing Endpoint: {url} ---")
    data = json.dumps({"username": "viewer", "password": "viewer123"}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            res_data = response.read().decode("utf-8")
            print(f"SUCCESS: Endpoint responded: {response.status}")
            print(f"Response: {res_data}")
    except urllib.error.HTTPError as e:
        print(f"HTTP ERROR: {e.code} - {e.reason}")
        try:
            print(f"Error Body: {e.read().decode('utf-8')}")
        except:
            pass
    except urllib.error.URLError as e:
        print(f"CONNECTION ERROR: Failed to reach server. Reason: {e.reason}")
        print("  - If this is 'Connection refused', the server is NOT running on this IP/port.")
        print("  - If the server is only running on 127.0.0.1, you cannot reach it via the local network IP.")
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}")

if __name__ == "__main__":
    check_db()
    check_network_endpoint("http://127.0.0.1:8000/api/auth/login")
    check_network_endpoint("http://10.220.31.241:8000/api/auth/login")
