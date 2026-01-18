"""
Unified Threat Detector
Healthcare Cyber-Resilience Platform

Integrates all detection layers into a single detection pipeline:
1. Feature extraction
2. Rule-based detection (Layer 1)
3. Autoencoder anomaly detection (Layer 2)
4. Graph reasoning (Layer 3)
5. Fusion (Layer 4)
"""

from typing import Dict, List
from .detection import calculate_risk_score, classify_attack
from .graphs import graph_analyze, get_graph_risk
from .fusion import fuse


def extract_features(log: Dict) -> Dict:
    """
    Extract relevant features from a log entry for ML analysis.
    
    Features:
        - Request volume indicators
        - Response time
        - Error rate
        - Payload characteristics
        - Authentication attempts
    """
    return {
        "req_per_sec": log.get("req_per_sec", 1),
        "response_time": log.get("response_time", 100),
        "error_rate": log.get("error_rate", 0.0),
        "unique_endpoints": log.get("unique_endpoints", 1),
        "payload_size": log.get("payload_size", 0),
        "failed_logins": log.get("failed_logins", 0),
        "unique_ports": log.get("unique_ports", 1),
        "status_code": log.get("status_code", 200),
        "path": log.get("path", "/"),
        "method": log.get("method", "GET"),
        "user_agent": log.get("user_agent", "unknown")
    }


def detect(log: Dict) -> Dict:
    """
    Main detection pipeline. Runs log through all detection layers.
    
    Pipeline:
        1. Extract features
        2. Rule-based detection → rule_score, attacks
        3. Autoencoder analysis → ae_score (anomaly score)
        4. Graph reasoning → graph_score, graph_attacks
        5. Fusion → final risk level
    
    Returns:
        risk_level: "LOW", "MEDIUM", or "HIGH"
        risk_score: Combined score (0.0 to 1.0)
        attacks: List of detected attack types
        reasons: List of detection reasons
    """
    reasons = []
    attacks = []
    
    # 1. Feature extraction
    features = extract_features(log)
    
    # 2. Rule-based detection (Layer 1)
    ip = log.get("client_ip", log.get("ip", "unknown"))
    path = log.get("path", log.get("endpoint", "/"))
    user_agent = log.get("user_agent", "unknown")
    status_code = log.get("status_code", 200)
    
    # Calculate rule-based risk
    rule_score = calculate_risk_score(
        request_count=features.get("req_per_sec", 1) * 10,
        error_count=int(features.get("error_rate", 0) * 10),
        time_window=10.0,
        has_sensitive_access=any(p in path.lower() for p in ["/admin", "/patients", "/config"]),
        path=path,
        user_agent=user_agent
    )
    
    # Get attack classification
    attack_info = classify_attack(path, user_agent, status_code, rule_score)
    if attack_info and attack_info.get("attack_type"):
        attacks.append(attack_info["attack_type"])
        if attack_info.get("description"):
            reasons.append(attack_info["description"])
    
    # 3. Autoencoder anomaly score (Layer 2)
    # This would come from the actual autoencoder in production
    # For now, estimate based on features
    ae_score = 0.0
    
    # High error rate = anomaly
    if features.get("error_rate", 0) > 0.5:
        ae_score += 0.4
        reasons.append("High error rate detected")
    
    # Unusual payload size = anomaly
    if features.get("payload_size", 0) > 5000:
        ae_score += 0.3
        reasons.append("Large payload size")
    
    # High request volume = anomaly
    if features.get("req_per_sec", 1) > 100:
        ae_score += 0.3
        reasons.append("High request volume")
    
    # Failed logins = credential stuffing
    if features.get("failed_logins", 0) > 5:
        ae_score += 0.4
        attacks.append("🔑 Brute Force / Credential Stuffing")
        reasons.append(f"{features['failed_logins']} failed login attempts")
    
    ae_score = min(1.0, ae_score)
    
    # 4. Graph reasoning (Layer 3)
    graph_out = graph_analyze(ip, path)
    graph_score = graph_out["score"]
    attacks.extend(graph_out["attacks"])
    reasons.extend(graph_out["reasons"])
    
    # 5. Fusion (Layer 4)
    result = fuse(rule_score, ae_score, graph_score, reasons)
    
    # Add attack names to result
    result["attacks"] = list(set(attacks))  # Remove duplicates
    result["ip"] = ip
    result["path"] = path
    
    return result


def detect_from_request(ip: str, path: str, user_agent: str, status_code: int) -> Dict:
    """
    Simplified detection for HTTP request analysis.
    """
    log = {
        "client_ip": ip,
        "path": path,
        "user_agent": user_agent,
        "status_code": status_code,
        "req_per_sec": 1,
        "error_rate": 0.1 if status_code >= 400 else 0.0,
        "payload_size": 100
    }
    return detect(log)
