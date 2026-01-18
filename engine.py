import asyncio
from datetime import datetime, timedelta
from typing import List, Dict
from .ingest import get_latest_logs, LOG_BUFFER
from .detection import detect_anomalies, get_traffic_stats

# Global State for Alerts
ACTIVE_ALERTS = []
TRAFFIC_STATS = {}
LAST_ACTIVITY_TIME = None

# Alert expiration time (seconds)
ALERT_EXPIRY_SECONDS = 30


async def sentinel_loop():
    """
    Background task that continuously monitors the log stream.
    Integrates with resilience for auto-blocking.
    """
    global TRAFFIC_STATS, LAST_ACTIVITY_TIME, ACTIVE_ALERTS
    
    # Import resilience for auto-blocking
    from .resilience import resilience, is_ip_blocked
    
    while True:
        try:
            # 1. Ingest - get only recent logs
            all_logs = get_latest_logs(500)
            
            # Filter to only logs from last 30 seconds
            now = datetime.now()
            recent_logs = []
            for log in all_logs:
                try:
                    ts = datetime.fromisoformat(log.get("timestamp", ""))
                    if (now - ts).total_seconds() < 30:
                        # Skip blocked IPs
                        if not is_ip_blocked(log.get("client_ip", "")):
                            recent_logs.append(log)
                except:
                    pass
            
            # 2. Detect
            if recent_logs:
                LAST_ACTIVITY_TIME = now
                new_alerts = detect_anomalies(recent_logs)
                TRAFFIC_STATS = get_traffic_stats(recent_logs)
                
                # 3. Alert / Respond + Resilience Integration
                if new_alerts:
                    for alert in new_alerts:
                        # Deduplicate - don't spam same IP
                        existing_ips = [a['ip'] for a in ACTIVE_ALERTS[-20:]]
                        if alert['ip'] not in existing_ips or alert['severity'] == 'HIGH':
                            print(f"!!! SENTINEL ALERT [{alert['severity']}]: {alert['attack_type']} from {alert['ip']} !!!")
                            ACTIVE_ALERTS.append(alert)
                            
                            # Resilience: Auto-block high-risk IPs
                            resilience.on_threat_detected(alert)
                            
                            # Keep alerts list manageable
                            if len(ACTIVE_ALERTS) > 100:
                                ACTIVE_ALERTS.pop(0)
                else:
                    # PEACE TIME: Traffic is flowing but it's CLEAN
                    # Aggressively clear old alerts to reset state quickly
                    if ACTIVE_ALERTS:
                        # Remove up to 5 oldest alerts per cycle (2s) usually
                        # But if we have valid clean traffic, clear even faster
                        if len(ACTIVE_ALERTS) > 0:
                            # 20% decay per cycle
                            decay_count = max(1, int(len(ACTIVE_ALERTS) * 0.2))
                            del ACTIVE_ALERTS[:decay_count]
            else:
                # No recent traffic - clear stale alerts
                if LAST_ACTIVITY_TIME and (now - LAST_ACTIVITY_TIME).total_seconds() > ALERT_EXPIRY_SECONDS:
                    # Fade out old alerts
                    if ACTIVE_ALERTS:
                        ACTIVE_ALERTS.pop(0)  # Remove oldest alert gradually
            
            # AUTOMATIC LIFECYCLE MAINTENANCE
            # This runs every loop iteration and handles:
            # - Auto-unblock expired IPs
            # - Auto-clean if too many alerts
            # - Auto-update system state
            resilience.auto_maintenance()
        
        except Exception as e:
            print(f"Sentinel Error: {e}")
            import traceback
            traceback.print_exc()
            
        await asyncio.sleep(2)  # Run every 2 seconds


def get_alerts():
    """Return recent alerts, filtered by age."""
    now = datetime.now()
    fresh_alerts = []
    
    for alert in ACTIVE_ALERTS[-15:]:
        try:
            alert_time = datetime.fromisoformat(alert.get("timestamp", ""))
            age = (now - alert_time).total_seconds()
            if age < 60:  # Only show alerts from last 60 seconds
                fresh_alerts.append(alert)
        except:
            pass
    
    return fresh_alerts


def get_stats():
    return TRAFFIC_STATS


def clear_alerts():
    """Manually clear all alerts."""
    global ACTIVE_ALERTS
    ACTIVE_ALERTS = []
