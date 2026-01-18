"""
Layer 1: Rule-Based Detection Engine
Healthcare Cyber-Resilience Platform

Detects anomalies using threshold-based rules.
Outputs a risk score (0.0 to 1.0) for fusion with other layers.
"""

from datetime import datetime, timedelta
from typing import List, Dict
from collections import defaultdict
import math


# Detection Thresholds (Lowered for better detection)
HIGH_REQUEST_THRESHOLD = 10  # Lowered from 20
HIGH_ERROR_RATE_THRESHOLD = 0.2  # Lowered from 0.3
RAPID_FIRE_THRESHOLD = 5  # Lowered from 10
DDOS_THRESHOLD = 50  # Lowered from 100

# Attack Type Definitions
ATTACK_TYPES = {
    "BOLA": {
        "name": "🔓 BOLA Attack",
        "full_name": "Broken Object Level Authorization",
        "description": "Attacker enumerating patient IDs to access unauthorized records"
    },
    "DDOS": {
        "name": "🌊 DDoS Attack",
        "full_name": "Distributed Denial of Service",
        "description": "Overwhelming the server with massive request flood"
    },
    "BRUTE_FORCE": {
        "name": "🔑 Brute Force",
        "full_name": "Credential Stuffing Attack",
        "description": "Repeated login attempts to guess credentials"
    },
    "DATA_EXFIL": {
        "name": "📤 Data Exfiltration",
        "full_name": "Data Breach Attempt",
        "description": "Unusual data transfer indicating potential breach"
    },
    "SCRAPING": {
        "name": "🕷️ Data Scraping",
        "full_name": "Automated Scraping Attack",
        "description": "Bot harvesting patient data systematically"
    },
    "INJECTION": {
        "name": "💉 Injection Attack",
        "full_name": "SQL/Command Injection",
        "description": "Malicious payloads in request parameters"
    },
    "XSS": {
        "name": "🔗 XSS Attack",
        "full_name": "Cross-Site Scripting",
        "description": "Malicious script injection attempt"
    },
    "SUSPICIOUS": {
        "name": "⚠️ Suspicious Activity",
        "full_name": "Anomalous Behavior",
        "description": "Unusual pattern requiring investigation"
    }
}


def calculate_risk_score(stats: Dict, logs_for_ip: List[Dict]) -> float:
    """
    Calculate a risk score (0.0 to 1.0) based on traffic patterns.
    This is the Layer 1 (Rules) contribution to the fusion formula.
    """
    risk = 0.0
    
    # Whitelist trusted sources (Localhost, Dashboard, Nurses)
    paths = [log.get("path", "") for log in logs_for_ip]
    user_agents = [log.get("user_agent", "") for log in logs_for_ip]
    
    # 0. Trusted Source Check
    # If predominantly localhost or Nurse traffic, reduce risk significantly
    is_localhost = all(str(log.get("client_ip", "")) in ["127.0.0.1", "::1", "localhost"] for log in logs_for_ip)
    is_nurse = any("Nurse" in ua for ua in user_agents)
    
    if (is_localhost or is_nurse) and stats["errors"] == 0:
        # Heavily discount risk for trusted traffic if no errors
        return 0.05
    
    # Factor 1: Request volume (0-0.5) - BOOSTED
    if stats["count"] > DDOS_THRESHOLD:
        risk += 0.5  # DDoS = max risk
    elif stats["count"] > HIGH_REQUEST_THRESHOLD:
        risk += 0.35
    elif stats["count"] > 5:
        risk += 0.2  # Moderate traffic adds more risk
    
    # Factor 2: Error rate (0-0.3)
    error_rate = stats["errors"] / stats["count"] if stats["count"] > 0 else 0
    risk += error_rate * 0.3
    
    # Factor 3: Rapid-fire detection (0-0.4) - BOOSTED
    if len(stats["recent"]) > RAPID_FIRE_THRESHOLD:
        velocity = len(stats["recent"]) / 10.0
        risk += min(0.4, velocity * 0.1)  # Double multiplier
    elif len(stats["recent"]) > 3:
        risk += 0.15  # More rapid request risk
    
    # Factor 4: Sensitive endpoint access (0-0.3) - BOOSTED
    sensitive_access = sum(1 for p in paths if "/patients/" in p)
    if sensitive_access > 3:
        risk += 0.3  # Doubled
    elif sensitive_access > 0:
        risk += 0.1  # Doubled
    
    return min(1.0, risk)


def get_severity_from_score(score: float) -> str:
    """
    Convert risk score to severity level.
    score < 0.3 → LOW
    0.3 <= score <= 0.7 → MEDIUM
    score > 0.7 → HIGH
    """
    if score < 0.3:
        return "LOW"
    elif score <= 0.7:
        return "MEDIUM"
    else:
        return "HIGH"


"""
Attack Type Rotation Counter
Ensures variety by cycling through attack types
"""
_attack_counter = 0

def classify_attack(stats: Dict, logs_for_ip: List[Dict]) -> Dict:
    """
    Classify the type of attack based on traffic patterns.
    """
    global _attack_counter
    import random
    
    paths = [log.get("path", "") for log in logs_for_ip]
    patient_id_accesses = sum(1 for p in paths if "/patients/" in p)
    error_rate = stats["errors"] / max(1, stats["count"])
    
    # All possible attack types in rotation order
    ALL_ATTACKS = ["BOLA", "DDOS", "BRUTE_FORCE", "SCRAPING", "DATA_EXFIL", "INJECTION", "XSS"]
    
    # Check for specific patterns first
    detected_type = None
    confidence = 0.75
    
    # Check for Injection patterns (highest priority - clear signature)
    injection_patterns = ["'", "union", "select", "--", "drop", "insert"]
    xss_patterns = ["script", "onerror", "javascript:", "<img", "<svg"]
    
    for path in paths:
        path_lower = path.lower()
        if any(p in path_lower for p in injection_patterns):
            detected_type = "INJECTION"
            confidence = 0.92
            break
        if any(p in path_lower for p in xss_patterns):
            detected_type = "XSS"
            confidence = 0.90
            break
    
    # If no injection, try to infer from stats
    if detected_type is None:
        if stats["count"] > DDOS_THRESHOLD:
            detected_type = "DDOS"
            confidence = 0.95
        elif error_rate > 0.4:
            detected_type = "BRUTE_FORCE"
            confidence = 0.88
        elif patient_id_accesses > 10:
            # Only classify BOLA if specific pattern
             detected_type = "BOLA"
             confidence = 0.65
        else:
             # Default to Suspicious if no clear pattern
             detected_type = "SUSPICIOUS"
             confidence = 0.5

    attack_info = ATTACK_TYPES.get(detected_type, ATTACK_TYPES["SUSPICIOUS"])
    return {
        "type_code": detected_type,
        "type_name": attack_info["name"],
        "full_name": attack_info["full_name"],
        "description": attack_info["description"],
        "confidence": min(0.99, confidence)
    }


# Track global rule-based risk
_rule_scores = []

def detect_anomalies(logs: List[Dict]) -> List[Dict]:
    """
    Enhanced anomaly detection with risk scoring.
    Returns alerts with severity based on score ranges.
    """
    global _rule_scores
    
    if not logs:
        return []
    
    anomalies = []
    now = datetime.now()
    
    # Group logs by IP
    ip_logs = defaultdict(list)
    ip_stats = defaultdict(lambda: {"count": 0, "errors": 0, "recent": []})
    
    for log in logs:
        ip = log.get("client_ip", "unknown")
        status = log.get("status_code", 200)
        timestamp = log.get("timestamp", "")
        
        ip_logs[ip].append(log)
        ip_stats[ip]["count"] += 1
        if status >= 400:
            ip_stats[ip]["errors"] += 1
        
        try:
            ts = datetime.fromisoformat(timestamp)
            if (now - ts).total_seconds() < 10:
                ip_stats[ip]["recent"].append(ts)
        except:
            pass
    
    # Analyze each IP
    for ip, stats in ip_stats.items():
        # Calculate risk score
        risk_score = calculate_risk_score(stats, ip_logs[ip])
        
        # Only alert if risk is above minimum threshold (lowered for sensitivity)
        if risk_score >= 0.1:
            # Track for global average
            _rule_scores.append(risk_score)
            if len(_rule_scores) > 100:
                _rule_scores.pop(0)
            
            # Get severity from score
            severity = get_severity_from_score(risk_score)
            
            # Classify attack type
            attack_info = classify_attack(stats, ip_logs[ip])
            
            # Build reason string
            reasons = []
            if stats["count"] > HIGH_REQUEST_THRESHOLD:
                reasons.append(f"Volume: {stats['count']} reqs")
            error_rate = stats["errors"] / stats["count"] if stats["count"] > 0 else 0
            if error_rate > 0.1:
                reasons.append(f"Errors: {error_rate*100:.0f}%")
            if len(stats["recent"]) > RAPID_FIRE_THRESHOLD:
                reasons.append(f"Speed: {len(stats['recent'])} in 10s")
            
            anomalies.append({
                "ip": ip,
                "severity": severity,
                "risk_score": round(risk_score, 3),
                "attack_type": attack_info["type_name"],
                "attack_code": attack_info["type_code"],
                "attack_full_name": attack_info["full_name"],
                "attack_description": attack_info["description"],
                "confidence": attack_info["confidence"],
                "reason": " | ".join(reasons) if reasons else "Anomalous pattern",
                "request_count": stats["count"],
                "error_count": stats["errors"],
                "timestamp": now.isoformat(),
                "type": attack_info["type_code"]
            })
    
    return anomalies


def get_rules_risk_score() -> float:
    """
    Get the average rule-based risk score (0.0 to 1.0).
    Used in the fusion formula.
    """
    if not _rule_scores:
        return 0.0
    return sum(_rule_scores) / len(_rule_scores)


def clear_rule_scores():
    """Clear all rule scores - called when no traffic detected."""
    global _rule_scores
    _rule_scores = []


def get_traffic_stats(logs: List[Dict]) -> Dict:
    """Generate traffic statistics for the API Traffic page."""
    if not logs:
        return {"endpoints": [], "methods": {}, "status_codes": {}}
    
    endpoints = defaultdict(int)
    methods = defaultdict(int)
    status_codes = defaultdict(int)
    
    for log in logs:
        endpoints[log.get("path", "/")] += 1
        methods[log.get("method", "GET")] += 1
        status_codes[str(log.get("status_code", 200))] += 1
    
    return {
        "endpoints": [{"path": k, "count": v} for k, v in sorted(endpoints.items(), key=lambda x: -x[1])[:10]],
        "methods": dict(methods),
        "status_codes": dict(status_codes)
    }
