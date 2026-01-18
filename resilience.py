"""
Cyber Resilience Lifecycle Module
Healthcare Cyber-Resilience Platform

Implements the 4-phase resilience cycle:
🔍 DETECT → 🚫 BLOCK → 🧹 CLEAN → ♻️ REACTIVATE
"""

from datetime import datetime, timedelta
from typing import Dict, List, Set
from collections import defaultdict
import asyncio


class ResilienceManager:
    """
    Manages the cyber resilience lifecycle AUTOMATICALLY.
    The full cycle runs without user intervention:
    
    🔍 DETECT → 🚫 BLOCK → 🧹 CLEAN → ♻️ REACTIVATE
    
    When HIGH risk is detected:
    1. IP is auto-blocked
    2. After quarantine expires, IP is auto-unblocked
    3. System auto-cleans old data
    4. System auto-returns to MONITORING
    """
    
    # Resilience States
    STATE_MONITORING = "MONITORING"
    STATE_DETECTING = "DETECTING"
    STATE_BLOCKING = "BLOCKING"
    STATE_CLEANING = "CLEANING"
    STATE_RECOVERED = "RECOVERED"
    
    def __init__(self):
        # Blocked IPs with block time and reason
        self.blocked_ips: Dict[str, Dict] = {}
        
        # Quarantine duration (seconds) - auto-unblock after this time
        self.quarantine_duration = 30  # 30 seconds for demo (faster visibility)
        
        # Auto-clean threshold - clean when this many alerts accumulate
        self.auto_clean_threshold = 30
        
        # Current system state
        self.current_state = self.STATE_MONITORING
        
        # Incident log
        self.incidents: List[Dict] = []
        
        # Stats
        self.total_blocks = 0
        self.total_cleans = 0
        self.total_reactivations = 0
        
        # Auto-block threshold (risk score) - LOWERED to block more attacks
        self.auto_block_threshold = 0.1  # Block at 10% risk - blocks almost everything
        
        # Track when last auto-maintenance ran
        self.last_maintenance = datetime.now()
    
    # =========================================================================
    # PHASE 1: DETECT (Already implemented in detection.py)
    # This phase uses the existing detection engine
    # =========================================================================
    
    def on_threat_detected(self, alert: Dict) -> Dict:
        """
        Called when a threat is detected.
        Decides whether to escalate to BLOCK phase.
        """
        self.current_state = self.STATE_DETECTING
        
        ip = alert.get("ip", "unknown")
        severity = alert.get("severity", "LOW")
        risk_score = alert.get("risk_score", 0)
        attack_type = alert.get("attack_type", "Unknown")
        
        # Log incident
        incident = {
            "timestamp": datetime.now().isoformat(),
            "phase": "DETECT",
            "ip": ip,
            "attack_type": attack_type,
            "severity": severity,
            "risk_score": risk_score,
            "action": "detected"
        }
        self.incidents.append(incident)
        
        # Auto-block if severity is HIGH or risk exceeds threshold
        if severity == "HIGH" or risk_score >= self.auto_block_threshold:
            return self.block_ip(ip, f"Auto-blocked: {attack_type}")
        
        return {"action": "monitor", "ip": ip, "reason": "Below auto-block threshold"}
    
    # =========================================================================
    # PHASE 2: BLOCK
    # Quarantine malicious IPs
    # =========================================================================
    
    def block_ip(self, ip: str, reason: str = "Manual block") -> Dict:
        """
        Block a malicious IP address.
        Adds to blocklist and logs the action.
        """
        self.current_state = self.STATE_BLOCKING
        
        if ip in self.blocked_ips:
            return {"action": "already_blocked", "ip": ip}
        
        self.blocked_ips[ip] = {
            "blocked_at": datetime.now().isoformat(),
            "reason": reason,
            "expires_at": (datetime.now() + timedelta(seconds=self.quarantine_duration)).isoformat()
        }
        
        self.total_blocks += 1
        
        # Log incident
        self.incidents.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "BLOCK",
            "ip": ip,
            "action": "blocked",
            "reason": reason
        })
        
        print(f"🚫 BLOCKED: {ip} - {reason}")
        
        return {"action": "blocked", "ip": ip, "reason": reason}
    
    def unblock_ip(self, ip: str) -> Dict:
        """Manually unblock an IP address."""
        if ip not in self.blocked_ips:
            return {"action": "not_found", "ip": ip}
        
        del self.blocked_ips[ip]
        
        self.incidents.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "REACTIVATE",
            "ip": ip,
            "action": "unblocked"
        })
        
        return {"action": "unblocked", "ip": ip}
    
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        return ip in self.blocked_ips
    
    def get_blocked_ips(self) -> List[Dict]:
        """Get list of all blocked IPs with details."""
        blocked_list = []
        for ip, details in self.blocked_ips.items():
            blocked_list.append({
                "ip": ip,
                **details
            })
        return blocked_list
    
    # =========================================================================
    # PHASE 3: CLEAN
    # Purge malicious data, reset compromised state
    # =========================================================================
    
    def clean_system(self) -> Dict:
        """
        Clean the system after an attack.
        - Clear infection traces
        - Reset compromised state
        - Purge malicious logs
        """
        self.current_state = self.STATE_CLEANING
        
        from .engine import ACTIVE_ALERTS, TRAFFIC_STATS
        from .ingest import LOG_BUFFER
        from .graphs import G, seen, node_events
        
        # Count items before cleaning
        alerts_cleared = len(ACTIVE_ALERTS)
        logs_cleared = len(LOG_BUFFER)
        nodes_cleared = len(G.nodes()) if G else 0
        
        # Clear active alerts
        ACTIVE_ALERTS.clear()
        
        # Clear log buffer
        LOG_BUFFER.clear()
        
        # Reset networkx graph
        G.clear()
        seen.clear()
        node_events.clear()
        
        # Reset traffic stats
        TRAFFIC_STATS.clear()
        
        self.total_cleans += 1
        
        # Log incident
        self.incidents.append({
            "timestamp": datetime.now().isoformat(),
            "phase": "CLEAN",
            "action": "system_cleaned",
            "alerts_cleared": alerts_cleared,
            "logs_cleared": logs_cleared,
            "nodes_cleared": nodes_cleared
        })
        
        print(f"🧹 CLEANED: {alerts_cleared} alerts, {logs_cleared} logs, {nodes_cleared} nodes")
        
        return {
            "action": "cleaned",
            "alerts_cleared": alerts_cleared,
            "logs_cleared": logs_cleared,
            "nodes_cleared": nodes_cleared
        }
    
    # =========================================================================
    # PHASE 4: REACTIVATE
    # Restore services and unblock expired IPs
    # =========================================================================
    
    def reactivate(self) -> Dict:
        """
        Reactivate the system after cleaning.
        - Unblock expired IPs
        - Reset to monitoring state
        - Resume normal operations
        """
        self.current_state = self.STATE_RECOVERED
        
        now = datetime.now()
        expired_ips = []
        
        # Find and remove expired blocks
        for ip, details in list(self.blocked_ips.items()):
            try:
                expires_at = datetime.fromisoformat(details["expires_at"])
                if now >= expires_at:
                    expired_ips.append(ip)
                    del self.blocked_ips[ip]
            except:
                pass
        
        if expired_ips:
            self.total_reactivations += len(expired_ips)
        
        # Log incident
        self.incidents.append({
            "timestamp": now.isoformat(),
            "phase": "REACTIVATE",
            "action": "system_reactivated",
            "ips_unblocked": len(expired_ips),
            "ips": expired_ips
        })
        
        # Return to monitoring
        self.current_state = self.STATE_MONITORING
        
        print(f"♻️ REACTIVATED: {len(expired_ips)} IPs released")
        
        return {
            "action": "reactivated",
            "ips_unblocked": len(expired_ips),
            "released_ips": expired_ips,
            "state": self.current_state
        }
    
    def full_recovery(self) -> Dict:
        """
        Perform full system recovery.
        CLEAN + REACTIVATE in one operation.
        """
        clean_result = self.clean_system()
        reactivate_result = self.reactivate()
        
        # Unblock all IPs
        all_blocked = list(self.blocked_ips.keys())
        self.blocked_ips.clear()
        
        return {
            "action": "full_recovery",
            "clean": clean_result,
            "reactivate": reactivate_result,
            "all_ips_unblocked": all_blocked,
            "state": self.STATE_MONITORING
        }
    
    # =========================================================================
    # STATUS & METRICS
    # =========================================================================
    
    def get_status(self) -> Dict:
        """Get current resilience status and metrics."""
        return {
            "state": self.current_state,
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_ips": self.get_blocked_ips(),
            "total_blocks": self.total_blocks,
            "total_cleans": self.total_cleans,
            "total_reactivations": self.total_reactivations,
            "incidents_count": len(self.incidents),
            "recent_incidents": self.incidents[-10:]
        }
    
    def get_lifecycle_stats(self) -> Dict:
        """Get resilience lifecycle statistics."""
        # Count incidents by phase
        phase_counts = defaultdict(int)
        for incident in self.incidents:
            phase_counts[incident.get("phase", "UNKNOWN")] += 1
        
        return {
            "detect_count": phase_counts.get("DETECT", 0),
            "block_count": phase_counts.get("BLOCK", 0),
            "clean_count": phase_counts.get("CLEAN", 0),
            "reactivate_count": phase_counts.get("REACTIVATE", 0),
            "current_state": self.current_state
        }
    
    # =========================================================================
    # AUTOMATIC MAINTENANCE (The Magic - No User Action Required!)
    # =========================================================================
    
    def auto_maintenance(self) -> Dict:
        """
        AUTOMATIC lifecycle maintenance.
        This runs every few seconds and handles:
        1. Auto-unblock expired IPs
        2. Auto-clean if too many alerts
        3. Auto-return to MONITORING state
        
        The user just watches - everything happens automatically!
        """
        now = datetime.now()
        actions_taken = []
        
        # 1. Auto-unblock expired IPs
        expired_ips = []
        for ip, details in list(self.blocked_ips.items()):
            try:
                expires_at = datetime.fromisoformat(details["expires_at"])
                if now >= expires_at:
                    expired_ips.append(ip)
                    del self.blocked_ips[ip]
                    print(f"♻️ AUTO-UNBLOCKED: {ip} (quarantine expired)")
            except:
                pass
        
        if expired_ips:
            self.total_reactivations += len(expired_ips)
            actions_taken.append(f"unblocked {len(expired_ips)} IPs")
            self.incidents.append({
                "timestamp": now.isoformat(),
                "phase": "REACTIVATE",
                "action": "auto_unblocked",
                "ips": expired_ips
            })
            
            # CLEAN: Remove alerts from unblocked IPs
            try:
                from .engine import ACTIVE_ALERTS
                before_count = len(ACTIVE_ALERTS)
                ACTIVE_ALERTS[:] = [a for a in ACTIVE_ALERTS if a.get("ip") not in expired_ips]
                cleaned = before_count - len(ACTIVE_ALERTS)
                if cleaned > 0:
                    print(f"🧹 CLEANED: {cleaned} alerts from unblocked IPs")
                    actions_taken.append(f"cleaned {cleaned} alerts")
            except Exception as e:
                pass
        
        # 2. Auto-clean if too many alerts
        try:
            from .engine import ACTIVE_ALERTS
            if len(ACTIVE_ALERTS) > self.auto_clean_threshold:
                # Keep only the most recent alerts
                alerts_to_remove = len(ACTIVE_ALERTS) - 20
                for _ in range(alerts_to_remove):
                    if ACTIVE_ALERTS:
                        ACTIVE_ALERTS.pop(0)
                actions_taken.append(f"cleaned {alerts_to_remove} old alerts")
                print(f"🧹 AUTO-CLEANED: {alerts_to_remove} old alerts")
        except:
            pass
        
        # 3. Trim incident log to prevent memory bloat
        if len(self.incidents) > 200:
            self.incidents = self.incidents[-100:]
        
        # 4. Update state based on current conditions
        if self.blocked_ips:
            self.current_state = self.STATE_BLOCKING
        elif actions_taken:
            self.current_state = self.STATE_RECOVERED
        else:
            self.current_state = self.STATE_MONITORING
        
        self.last_maintenance = now
        
        return {
            "maintenance_ran": True,
            "actions": actions_taken,
            "blocked_ips": len(self.blocked_ips),
            "state": self.current_state
        }


# Global resilience manager instance
resilience = ResilienceManager()


# Convenience functions
def detect_and_respond(alert: Dict) -> Dict:
    """Process an alert through the resilience lifecycle."""
    return resilience.on_threat_detected(alert)


def block_ip(ip: str, reason: str = "Manual block") -> Dict:
    """Block an IP address."""
    return resilience.block_ip(ip, reason)


def unblock_ip(ip: str) -> Dict:
    """Unblock an IP address."""
    return resilience.unblock_ip(ip)


def clean_system() -> Dict:
    """Clean the system."""
    return resilience.clean_system()


def reactivate() -> Dict:
    """Reactivate the system."""
    return resilience.reactivate()


def full_recovery() -> Dict:
    """Perform full system recovery."""
    return resilience.full_recovery()


def get_resilience_status() -> Dict:
    """Get resilience status."""
    return resilience.get_status()


def is_ip_blocked(ip: str) -> bool:
    """Check if IP is blocked."""
    return resilience.is_blocked(ip)
