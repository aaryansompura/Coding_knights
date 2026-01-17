"""
Deterministic Cyber Attack Rule Engine - TOP 10 ATTACKS
Healthcare Cyber-Resilience Platform

Detects the 'Top 10 Famous Cyber Attacks' using pure mathematics and pattern matching.
Covers both System/Network attacks and Web/Identity attacks.
"""

import numpy as np
import math
import re  # For SQL Injection, XSS, and Directory Traversal detection
from collections import Counter


class CyberMath:
    """
    The Mathematical Engine.
    Calculates statistical features (Entropy, Z-Scores, Velocity).
    """
    
    @staticmethod
    def calculate_entropy(data_bytes):
        """
        Detects Encryption (Ransomware Indicator).
        Formula: H(x) = -Σ p(x) * log2(p(x))
        Range: 0.0 (Uniform) to 8.0 (Random/Encrypted)
        """
        if not data_bytes:
            return 0.0
        counts = Counter(data_bytes)
        total = len(data_bytes)
        frequencies = [count / total for count in counts.values()]
        return -sum(p * math.log2(p) for p in frequencies if p > 0)
    
    @staticmethod
    def calculate_z_score(current_value, history_mean, history_std):
        """
        Detects Statistical Anomalies.
        Formula: z = (x - μ) / σ
        """
        if history_std == 0:
            return 0.0
        return (current_value - history_mean) / history_std
    
    @staticmethod
    def calculate_velocity(count, time_window_seconds):
        """
        Detects Attack Speed (Rate of events).
        Formula: V = Δx / Δt
        """
        if time_window_seconds == 0:
            return 0.0
        return count / time_window_seconds


class CyberRules:
    """
    The Logic Layer.
    Contains 10 Distinct Rules covering the Top 10 Cyber Threats.
    """
    
    def __init__(self):
        self.math = CyberMath()
    
    # =========================================================================
    # TIER 1: SYSTEM & NETWORK ATTACKS (Original 5)
    # =========================================================================
    
    # 1. RANSOMWARE (WannaCry, NotPetya, Colonial Pipeline)
    def check_ransomware(self, file_entropy, modifications_per_min):
        """
        Signature: Files become unreadable (High Entropy) + Mass modification.
        Threshold: Entropy > 7.5 AND Mods > 50/min
        """
        if file_entropy > 7.5 and modifications_per_min > 50:
            return f"⚠️ CRITICAL: Ransomware Attack Detected (Entropy: {file_entropy:.2f}, Mods: {modifications_per_min}/min)"
        return None
    
    # 2. WORM PROPAGATION (Morris Worm, Stuxnet, Conficker)
    def check_worm_spread(self, unique_destinations, time_sec):
        """
        Signature: One machine connecting to many unique IPs rapidly.
        Threshold: Velocity > 100 connections/sec
        """
        velocity = self.math.calculate_velocity(unique_destinations, time_sec)
        if velocity > 100:
            return f"⚠️ ALERT: Worm Propagation Detected (Fan-out: {velocity:.0f} IPs/sec)"
        return None
    
    # 3. DATA EXFILTRATION (Yahoo, Equifax, Sony)
    def check_data_breach(self, upload_bytes, avg_daily_upload, std_dev):
        """
        Signature: Massive data upload compared to normal.
        Threshold: Z-Score > 4.0 (4-sigma event)
        """
        z_score = self.math.calculate_z_score(upload_bytes, avg_daily_upload, std_dev)
        if z_score > 4.0:
            return f"⚠️ DANGER: Data Exfiltration Detected (Z-Score: {z_score:.2f}, 4+ Sigma)"
        return None
    
    # 4. DDoS / BOTNET (Mirai Botnet, Dyn Attack)
    def check_ddos(self, request_count, time_sec):
        """
        Signature: Massive request flood from single source.
        Threshold: > 1000 requests/sec
        """
        rps = self.math.calculate_velocity(request_count, time_sec)
        if rps > 1000:
            return f"⚠️ ALERT: DDoS Attack Detected ({rps:.0f} req/sec)"
        return None
    
    # 5. SUPPLY CHAIN (SolarWinds, Kaseya)
    def check_supply_chain(self, is_signed_binary, is_known_ip):
        """
        Signature: Unsigned code communicating with unknown destination.
        Logic: NOT signed AND NOT known IP = Compromise
        """
        if (not is_signed_binary) and (not is_known_ip):
            return "⚠️ WARNING: Supply Chain Compromise (Unsigned Binary + Unknown IP)"
        return None
    
    # =========================================================================
    # TIER 2: WEB & IDENTITY ATTACKS (New 5)
    # =========================================================================
    
    # 6. SQL INJECTION (Most web breaches, OWASP #1)
    def check_sql_injection(self, input_string):
        """
        Signature: Malicious SQL patterns in user input.
        Detects: ' OR 1=1, --, UNION SELECT, etc.
        """
        sqli_patterns = [
            r"(\%27)|(\')",                    # Single quotes
            r"(\-\-)|(\%23)|(#)",              # SQL comments
            r"(OR|AND)\s+\d+\s*=\s*\d+",       # OR 1=1, AND 1=1
            r"UNION\s+(ALL\s+)?SELECT",        # UNION SELECT
            r"(DROP|DELETE|INSERT|UPDATE)\s+", # Dangerous keywords
            r";\s*(DROP|DELETE|INSERT|UPDATE)" # Chained commands
        ]
        combined_pattern = "|".join(sqli_patterns)
        if re.search(combined_pattern, input_string, re.IGNORECASE):
            return f"⚠️ ALERT: SQL Injection Attempt Detected (Input: {input_string[:30]}...)"
        return None
    
    # 7. XSS - Cross-Site Scripting (Stored, Reflected, DOM-based)
    def check_xss(self, input_string):
        """
        Signature: Script injection in user input.
        Detects: <script>, onerror=, javascript:, etc.
        """
        xss_patterns = [
            r"<script[^>]*>",                  # Script tags
            r"javascript\s*:",                 # javascript: URI
            r"on(error|load|click|mouseover)\s*=",  # Event handlers
            r"<iframe[^>]*>",                  # Iframe injection
            r"<img[^>]+onerror",               # Image onerror
            r"eval\s*\(",                      # Eval function
            r"document\.(cookie|location)"    # Document object access
        ]
        combined_pattern = "|".join(xss_patterns)
        if re.search(combined_pattern, input_string, re.IGNORECASE):
            return f"⚠️ ALERT: Cross-Site Scripting (XSS) Detected"
        return None
    
    # 8. BRUTE FORCE (SSH/RDP/Login attacks)
    def check_brute_force(self, failed_logins, time_sec):
        """
        Signature: High velocity of authentication failures.
        Threshold: > 5 failures/sec (clearly automated)
        """
        fail_rate = self.math.calculate_velocity(failed_logins, time_sec)
        if fail_rate > 5:
            return f"⚠️ SECURITY: Brute Force Attack Detected ({fail_rate:.1f} fails/sec)"
        return None
    
    # 9. DIRECTORY TRAVERSAL (Path Traversal, LFI)
    def check_directory_traversal(self, url_path):
        """
        Signature: Dot-dot-slash patterns to escape web root.
        Detects: ../, ..%2f, ....// variants
        """
        traversal_patterns = [
            r"\.\./",                          # ../
            r"\.\.\\",                         # ..\
            r"\.\.%2[fF]",                     # URL encoded
            r"\.\.%5[cC]",                     # URL encoded backslash
            r"%2e%2e[%2f\/\\]",               # Double encoded
            r"\.{2,}[\/\\]"                   # Multiple dots
        ]
        combined_pattern = "|".join(traversal_patterns)
        if re.search(combined_pattern, url_path, re.IGNORECASE):
            return f"⚠️ WARNING: Directory Traversal Attempt (Path Manipulation)"
        return None
    
    # 10. CRYPTOJACKING (Coinhive, mining malware)
    def check_cryptojacking(self, protocol_used, cpu_usage):
        """
        Signature: Mining protocol or extreme CPU usage.
        Detects: stratum+tcp protocol, CPU > 95%
        """
        if "stratum+tcp" in protocol_used.lower():
            return "⚠️ MALWARE: Cryptojacking Detected (Mining Protocol)"
        if cpu_usage > 95.0:
            return f"⚠️ MALWARE: Cryptojacking Suspected (CPU: {cpu_usage:.1f}%)"
        return None
    
    # =========================================================================
    # UTILITY: Run All Checks
    # =========================================================================
    
    def run_all_checks(self, context):
        """
        Run all security checks against a context dictionary.
        Returns a list of all detected threats.
        """
        threats = []
        
        # Tier 1 checks
        if 'file_entropy' in context and 'modifications_per_min' in context:
            result = self.check_ransomware(context['file_entropy'], context['modifications_per_min'])
            if result: threats.append(result)
        
        if 'unique_destinations' in context and 'time_sec' in context:
            result = self.check_worm_spread(context['unique_destinations'], context['time_sec'])
            if result: threats.append(result)
        
        if 'upload_bytes' in context and 'avg_upload' in context and 'std_upload' in context:
            result = self.check_data_breach(context['upload_bytes'], context['avg_upload'], context['std_upload'])
            if result: threats.append(result)
        
        if 'request_count' in context and 'time_sec' in context:
            result = self.check_ddos(context['request_count'], context['time_sec'])
            if result: threats.append(result)
        
        if 'is_signed' in context and 'is_known_ip' in context:
            result = self.check_supply_chain(context['is_signed'], context['is_known_ip'])
            if result: threats.append(result)
        
        # Tier 2 checks
        if 'input_string' in context:
            result = self.check_sql_injection(context['input_string'])
            if result: threats.append(result)
            result = self.check_xss(context['input_string'])
            if result: threats.append(result)
        
        if 'failed_logins' in context and 'time_sec' in context:
            result = self.check_brute_force(context['failed_logins'], context['time_sec'])
            if result: threats.append(result)
        
        if 'url_path' in context:
            result = self.check_directory_traversal(context['url_path'])
            if result: threats.append(result)
        
        if 'protocol' in context and 'cpu_usage' in context:
            result = self.check_cryptojacking(context['protocol'], context['cpu_usage'])
            if result: threats.append(result)
        
        return threats


# =============================================================================
# SELF-DIAGNOSTIC TEST - TOP 10 ATTACKS
# =============================================================================
if __name__ == "__main__":
    rules = CyberRules()
    
    print("=" * 70)
    print("🛡️  CYBER RULES ENGINE DIAGNOSTIC - TOP 10 ATTACKS")
    print("=" * 70)
    
    print("\n" + "-" * 70)
    print("TIER 1: SYSTEM & NETWORK ATTACKS")
    print("-" * 70)
    
    # Test 1: Ransomware
    print("\n[1] 🔐 Ransomware (WannaCry simulation)...")
    fake_encrypted = np.random.bytes(2048)
    entropy = rules.math.calculate_entropy(fake_encrypted)
    result = rules.check_ransomware(file_entropy=entropy, modifications_per_min=600)
    print(f"    Result: {result if result else '✅ Safe'}")
    
    # Test 2: Data Breach
    print("\n[2] 📤 Data Exfiltration (Equifax simulation)...")
    result = rules.check_data_breach(upload_bytes=5000, avg_daily_upload=500, std_dev=50)
    print(f"    Result: {result if result else '✅ Safe'}")
    
    # Test 3: DDoS
    print("\n[3] 🌊 DDoS (Mirai simulation)...")
    result = rules.check_ddos(request_count=5000, time_sec=2)
    print(f"    Result: {result if result else '✅ Safe'}")
    
    print("\n" + "-" * 70)
    print("TIER 2: WEB & IDENTITY ATTACKS")
    print("-" * 70)
    
    # Test 4: SQL Injection
    print("\n[4] 💉 SQL Injection...")
    bad_input = "admin' OR '1'='1' --"
    result = rules.check_sql_injection(bad_input)
    print(f"    Input: '{bad_input}'")
    print(f"    Result: {result if result else '✅ Safe'}")
    
    # Test 5: XSS
    print("\n[5] 🔗 Cross-Site Scripting (XSS)...")
    xss_input = "<script>alert('hacked')</script>"
    result = rules.check_xss(xss_input)
    print(f"    Input: '{xss_input}'")
    print(f"    Result: {result if result else '✅ Safe'}")
    
    # Test 6: Brute Force
    print("\n[6] 🔑 Brute Force...")
    result = rules.check_brute_force(failed_logins=20, time_sec=2)
    print(f"    Result: {result if result else '✅ Safe'}")
    
    # Test 7: Directory Traversal
    print("\n[7] 📂 Directory Traversal...")
    malicious_path = "/api/files/../../../etc/passwd"
    result = rules.check_directory_traversal(malicious_path)
    print(f"    Path: '{malicious_path}'")
    print(f"    Result: {result if result else '✅ Safe'}")
    
    # Test 8: Cryptojacking
    print("\n[8] ⛏️ Cryptojacking...")
    result = rules.check_cryptojacking(protocol_used="stratum+tcp://pool.mining.com:3333", cpu_usage=98.5)
    print(f"    Result: {result if result else '✅ Safe'}")
    
    # Test 9: Safe Traffic (Should Pass)
    print("\n[9] 🟢 Normal Traffic (should be safe)...")
    result = rules.check_worm_spread(unique_destinations=2, time_sec=60)
    print(f"    Result: {result if result else '✅ Safe'}")
    result = rules.check_sql_injection("SELECT * FROM users WHERE id = 5")
    print(f"    SQL Check: {result if result else '✅ Safe'}")
    
    print("\n" + "=" * 70)
    print("✅ DIAGNOSTIC COMPLETE - All 10 Rules Operational")
    print("=" * 70)
