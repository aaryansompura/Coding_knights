"""
Performance Evaluation Script
Healthcare Cyber-Resilience Platform

Generates a Confusion Matrix and Classification Report by testing the 
Logic Layers (Rule-Based + AI) against synthetic ground truth data.
"""

import sys
import os
import random
import numpy as np
from datetime import datetime
from typing import List, Dict
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Add app to path to import detection logic
sys.path.append(os.path.join(os.getcwd(), "app"))

try:
    from app.sentinel.detection import detect_anomalies
except ImportError:
    # Handle running from root or backend
    sys.path.append(os.getcwd())
    from app.sentinel.detection import detect_anomalies

# ==========================================
# 1. SETUP TEST DATA GENERATOR
# ==========================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "HospitalApp/1.0 (Nurse)",
    "HospitalApp/1.0 (Doctor)",
]

ATTACK_USER_AGENTS = [
    "sqlmap/1.6",
    "Nmap/7.92",
    "Nikto/2.1.6",
    "Python-urllib/3.8",
    "Mozilla/5.0" # Sometimes they look normal
]

NORMAL_PATHS = [
    "/api/v1/patients/P-1001",
    "/api/v1/patients/P-1002/vitals",
    "/api/v1/auth/login",
    "/api/v1/dashboard/stats"
]

ATTACK_SCENARIOS = {
    "SQLi": ["/api/v1/patients/' OR '1'='1", "/api/v1/login'--"],
    "XSS": ["/api/v1/search?q=<script>alert(1)</script>", "/img?src=x onerror=alert(1)"],
    "Travers": ["/api/v1/../../etc/passwd", "/config/../secret"],
    "BOLA": ["/api/v1/patients/P-9999"] # Requires context but we simulate behavior
}

def generate_test_dataset(n_normal=1000, n_attack=1000):
    """Generate labeled synthetic requests"""
    dataset = []
    
    print(f"Generating {n_normal} Normal and {n_attack} Attack samples...")
    print("(Using synthetic logs to test Sentinel Logic Engine)")
    
    # 1. Normal Traffic
    for _ in range(n_normal):
        sample = {
            "ip": f"192.168.1.{random.randint(50, 200)}",
            "path": random.choice(NORMAL_PATHS),
            "ua": random.choice(USER_AGENTS),
            "status": 200,
            "label": "BENIGN"
        }
        dataset.append(sample)
        
    # 2. Attack Traffic
    for _ in range(n_attack):
        attack_type = random.choice(list(ATTACK_SCENARIOS.keys()))
        path = random.choice(ATTACK_SCENARIOS[attack_type])
        
        sample = {
            "ip": f"10.0.0.{random.randint(10, 99)}", # Attacker IP range
            "path": path,
            "ua": random.choice(ATTACK_USER_AGENTS),
            "status": 200, # Attacks often get 200 if successful, or 403
            "label": "ATTACK" # We classify broadly as ATTACK
        }
        dataset.append(sample)
    
    random.shuffle(dataset)
    return dataset

# ==========================================
# 2. EVALUATION LOOP
# ==========================================

def run_evaluation():
    print("="*60)
    print("SENTINEL PERFORMANCE EVALUATION MATRIX")
    print("="*60)
    
    # Generate Data
    dataset = generate_test_dataset()
    
    y_true = []
    y_pred = []
    
    print("\nRunning Sentinel Detection on 2000 samples...")
    print("---------------------------------------------")
    
    for i, sample in enumerate(dataset):
        # Ground Truth
        truth = sample["label"]
        y_true.append(truth)
        
        # Create log entry format expected by detection.py
        log = {
            "client_ip": sample["ip"],
            "path": sample["path"],
            "user_agent": sample["ua"],
            "status_code": sample["status"],
            "timestamp": datetime.now().isoformat(),
            "method": "GET"
        }
        
        # Prediction
        # detect_anomalies takes a list of logs and returns list of alerts
        # This tests Layer 1 (Rules) primarily as autoencoder needs training context
        alerts = detect_anomalies([log])
        
        # If any alert is returned, we predict ATTACK
        if len(alerts) > 0:
            pred = "ATTACK"
        else:
            pred = "BENIGN"
        
        y_pred.append(pred)
        
        if i % 500 == 0:
            print(f"Processed {i}/2000 items...")
            
    print("Processing Complete.\n")
    
    # ==========================================
    # 3. REPORT GENERATION
    # ==========================================
    
    print("CONFUSION MATRIX:")
    print("-" * 30)
    # [TN, FP]
    # [FN, TP]
    cm = confusion_matrix(y_true, y_pred, labels=["BENIGN", "ATTACK"])
    tn, fp, fn, tp = cm.ravel()
    
    print(f"{'':<15} {'Pred: BENIGN':<15} {'Pred: ATTACK':<15}")
    print(f"{'Actual: BENIGN':<15} {tn:<15} {fp:<15}")
    print(f"{'Actual: ATTACK':<15} {fn:<15} {tp:<15}")
    print("-" * 30)
    
    print("\nCLASSIFICATION REPORT:")
    print(classification_report(y_true, y_pred, target_names=["BENIGN", "ATTACK"]))
    
    print("\nKEY METRICS:")
    accuracy = accuracy_score(y_true, y_pred)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print(f"  * Accuracy:  {accuracy:.1%}")
    print(f"  * Precision: {precision:.1%} (How many detected attacks were real?)")
    print(f"  * Recall:    {recall:.1%}    (How many real attacks were detected?)")
    print(f"  * F1-Score:  {f1:.1%}    (Balance)")
    
    print("="*60)

if __name__ == "__main__":
    run_evaluation()
