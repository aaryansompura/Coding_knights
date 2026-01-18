"""
Layer 4: Risk Fusion Engine
Healthcare Cyber-Resilience Platform

Combines outputs from all detection layers:
- Layer 1: Rule-based detection
- Layer 2: Autoencoder anomaly detection  
- Layer 3: Graph reasoning

Formula: Risk = 0.4 * rules + 0.4 * autoencoder + 0.2 * graph
"""

from typing import Dict, List


def fuse(rule_score: float, ae_score: float, graph_score: float, reasons: List[str] = None) -> Dict:
    """
    Fuse risk scores from all detection layers.
    
    Args:
        rule_score: Risk from rule-based detection (0.0 to 1.0)
        ae_score: Risk from autoencoder (0.0 to 1.0)
        graph_score: Risk from graph reasoning (0.0 to 1.0)
        reasons: List of reasons/explanations
    
    Returns:
        risk_level: "LOW", "MEDIUM", or "HIGH"
        risk_score: Combined score (0.0 to 1.0)
        reasons: List of detection reasons
    """
    # Fusion formula: weighted average
    risk = 0.4 * rule_score + 0.4 * ae_score + 0.2 * graph_score
    
    # Clamp to valid range
    risk = max(0.0, min(1.0, risk))
    
    # Determine risk level
    if risk > 0.7:
        level = "HIGH"
    elif risk > 0.4:
        level = "MEDIUM"
    else:
        level = "LOW"
    
    return {
        "risk_level": level,
        "risk_score": round(risk, 3),
        "reasons": reasons or [],
        "layer_scores": {
            "rules": round(rule_score, 3),
            "autoencoder": round(ae_score, 3),
            "graph": round(graph_score, 3)
        }
    }


def get_severity_from_risk(risk_score: float) -> str:
    """Convert risk score to severity string."""
    if risk_score >= 0.7:
        return "HIGH"
    elif risk_score >= 0.4:
        return "MEDIUM"
    else:
        return "LOW"


def explain_fusion(rule_score: float, ae_score: float, graph_score: float) -> str:
    """
    Generate human-readable explanation of the fusion calculation.
    """
    risk = 0.4 * rule_score + 0.4 * ae_score + 0.2 * graph_score
    
    explanation = f"""
RISK FUSION CALCULATION
═══════════════════════

Layer 1 (Rules):      {rule_score:.2f} × 0.4 = {rule_score * 0.4:.3f}
Layer 2 (Autoencoder): {ae_score:.2f} × 0.4 = {ae_score * 0.4:.3f}
Layer 3 (Graph):      {graph_score:.2f} × 0.2 = {graph_score * 0.2:.3f}
────────────────────────────────────
TOTAL RISK:           {risk:.3f} ({get_severity_from_risk(risk)})
"""
    return explanation.strip()
