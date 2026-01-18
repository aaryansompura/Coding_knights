"""
Layer 3: Graph-Based Reasoning Engine
Healthcare Cyber-Resilience Platform

Uses NetworkX for graph analysis.
Detects reconnaissance, port scans, and coordinated attacks.
"""

import networkx as nx
from collections import defaultdict
from datetime import datetime
from typing import Dict, List

# ============================================
# GRAPH STRUCTURE (networkx)
# ============================================

G = nx.Graph()
seen = set()  # Track (ip, endpoint) pairs
MAX_EDGES = 1000

# Event history for nodes
node_events: Dict[str, List[Dict]] = defaultdict(list)


def graph_analyze(ip: str, endpoint: str) -> Dict:
    """
    Analyze IP-endpoint interaction in the graph.
    
    Returns:
        score: 0.0 to 1.0 risk score
        attacks: List of detected attack types
        reasons: List of reasons for the score
    """
    global G, seen
    
    # Clear graph if too large (memory management)
    if len(G.edges) > MAX_EDGES:
        G.clear()
        seen.clear()
        node_events.clear()
    
    # Check if this is a new interaction
    is_new = (ip, endpoint) not in seen
    seen.add((ip, endpoint))
    
    # Add edge to graph
    G.add_edge(ip, endpoint)
    
    # Calculate risk score
    score = 0.0
    attacks = []
    reasons = []
    
    # Factor 1: Fan-out (IP accessing many endpoints = reconnaissance)
    if G.degree(ip) > 10:
        score += 0.5
        attacks.append("🕵️ Reconnaissance / Enumeration")
        reasons.append(f"IP accessed {G.degree(ip)} unique endpoints")
    elif G.degree(ip) > 5:
        score += 0.3
        attacks.append("🔍 Port Scan / Probing")
        reasons.append(f"IP accessed {G.degree(ip)} endpoints")
    
    # Factor 2: New interaction bonus
    if is_new:
        score += 0.2
        reasons.append("New IP-endpoint interaction")
    
    # Factor 3: Sensitive endpoint access
    sensitive_patterns = ["/admin", "/config", "/patients", "/vitals", "/debug"]
    for pattern in sensitive_patterns:
        if pattern in endpoint.lower():
            score += 0.3
            attacks.append("🎯 Sensitive Endpoint Access")
            reasons.append(f"Accessed sensitive path: {pattern}")
            break
    
    # Factor 4: Attack pattern in path
    if "'" in endpoint or "union" in endpoint.lower() or "select" in endpoint.lower():
        score += 0.5
        attacks.append("💉 SQL Injection")
        reasons.append("SQL injection pattern in request")
    
    if "<script" in endpoint.lower() or "javascript:" in endpoint.lower():
        score += 0.5
        attacks.append("🔗 XSS (Cross-Site Scripting)")
        reasons.append("XSS pattern in request")
    
    return {
        "score": min(score, 1.0),
        "attacks": attacks,
        "reasons": reasons
    }


def process_event(event: Dict):
    """
    Process a security event and update the graph.
    """
    ip = event.get("client_ip", "unknown")
    endpoint = event.get("path", "/")
    
    # Store event history
    node_events[ip].append({
        "path": endpoint,
        "status": event.get("status_code", 200),
        "time": event.get("timestamp", datetime.now().isoformat())
    })
    
    # Keep history manageable
    if len(node_events[ip]) > 50:
        node_events[ip] = node_events[ip][-50:]
    
    # Run graph analysis
    return graph_analyze(ip, endpoint)


def get_graph_risk() -> float:
    """
    Get the current graph-based risk score (0.0 to 1.0).
    Used in the fusion formula: 0.4*rules + 0.4*ae + 0.2*graph
    """
    if not G.nodes():
        return 0.0
    
    # Get all IP nodes (those with degree > 0)
    ip_risks = []
    for node in G.nodes():
        # IPs typically have numeric octets
        if any(c.isdigit() for c in str(node)) and "." in str(node):
            degree = G.degree(node)
            
            # Calculate risk based on degree (fan-out)
            if degree > 10:
                ip_risks.append(0.8)
            elif degree > 5:
                ip_risks.append(0.5)
            elif degree > 2:
                ip_risks.append(0.2)
            else:
                ip_risks.append(0.1)
    
    if not ip_risks:
        return 0.0
    
    # Combine: use max risk with average influence
    avg_risk = sum(ip_risks) / len(ip_risks)
    max_risk = max(ip_risks)
    
    combined = 0.6 * max_risk + 0.4 * avg_risk
    
    return round(combined, 3)


def get_graph_stats() -> Dict:
    """Get graph statistics for the dashboard."""
    # Count IP nodes vs endpoint nodes
    ip_nodes = []
    endpoint_nodes = []
    
    for node in G.nodes():
        node_str = str(node)
        # Check if it's an IP (has dots and numbers)
        if "." in node_str and any(c.isdigit() for c in node_str):
            ip_nodes.append(node_str)
        else:
            endpoint_nodes.append(node_str)
    
    # Find high-risk IPs (high degree)
    high_risk_ips = []
    for ip in ip_nodes:
        degree = G.degree(ip)
        if degree > 5:
            risk = min(1.0, 0.3 + (degree - 5) * 0.1)
            high_risk_ips.append({"ip": ip, "risk": round(risk, 2), "endpoints": degree})
    
    # Sort by risk
    high_risk_ips.sort(key=lambda x: x["risk"], reverse=True)
    
    return {
        "total_nodes": len(G.nodes()),
        "ip_count": len(ip_nodes),
        "endpoint_count": len(endpoint_nodes),
        "edge_count": len(G.edges()),
        "high_risk_ips": high_risk_ips[:10],
        "graph_risk_score": get_graph_risk()
    }


def get_visualization_data() -> Dict:
    """Get data for network visualization (vis.js format)."""
    nodes = []
    edges = []
    
    for node in G.nodes():
        node_str = str(node)
        # Determine if IP or endpoint
        is_ip = "." in node_str and any(c.isdigit() for c in node_str)
        
        degree = G.degree(node)
        risk = min(1.0, degree * 0.1) if is_ip else 0.0
        
        nodes.append({
            "id": node_str,
            "label": node_str[:20] + "..." if len(node_str) > 20 else node_str,
            "type": "ip" if is_ip else "endpoint",
            "risk": round(risk, 2),
            "degree": degree
        })
    
    for edge in G.edges():
        edges.append({
            "from": str(edge[0]),
            "to": str(edge[1])
        })
    
    return {
        "nodes": nodes[-100:],  # Limit for performance
        "edges": edges[-200:]
    }


# Legacy compatibility
security_graph = type('SecurityGraph', (), {
    'nodes': node_events,
    'edges': list(G.edges()) if G.edges() else []
})()
