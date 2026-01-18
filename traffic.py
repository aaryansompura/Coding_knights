"""
Multi-Attack Traffic Simulator - TOP 10 ATTACKS
Healthcare Cyber-Resilience Platform

Simulates all 10 types of cyber attacks alongside normal hospital traffic.
Matches the rules defined in rules.py
"""

import asyncio
import httpx
import random
import logging
import sys
from typing import List

# Configuration
BASE_URL = "http://127.0.0.1:8000/api/v1"
PATIENTS_COUNT = 50

# Setup logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Simulator")


class Actor:
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.client = httpx.AsyncClient(headers={"User-Agent": f"HospitalApp/1.0 ({role})"})

    async def run(self):
        logger.info(f"🏥 {self.name} ({self.role}) starting...")
        while True:
            try:
                await self.perform_action()
            except Exception as e:
                pass
            await asyncio.sleep(random.uniform(0.5, 3.0))

    async def perform_action(self):
        pass


# =============================================================================
# NORMAL TRAFFIC
# =============================================================================

class Nurse(Actor):
    """Normal hospital staff - legitimate traffic"""
    async def perform_action(self):
        p_id = f"P-{random.randint(1000, 1000 + PATIENTS_COUNT - 1)}"
        action = random.choice(["view_patient", "check_vitals"])
        
        if action == "view_patient":
            await self.client.get(f"{BASE_URL}/patients/{p_id}")
        elif action == "check_vitals":
            await self.client.get(f"{BASE_URL}/patients/{p_id}/vitals")


# =============================================================================
# TIER 1: SYSTEM & NETWORK ATTACKS
# =============================================================================

class BOLAAttacker(Actor):
    """
    🔓 BOLA Attack (Broken Object Level Authorization)
    Rapidly iterates through patient IDs to access unauthorized records.
    """
    def __init__(self):
        super().__init__("BOLA-Attacker", "Attacker")
        self.client.headers["User-Agent"] = "BurpSuite/2.0"
        # Simulate unique attacker IP
        self.client.headers["X-Forwarded-For"] = f"192.168.1.{random.randint(100, 110)}"

    async def perform_action(self):
        logger.warning("🔓 BOLA Attack: Enumerating patient IDs...")
        for _ in range(15):
            target_id = f"P-{random.randint(1000, 2000)}"
            await self.client.get(f"{BASE_URL}/patients/{target_id}")
            await asyncio.sleep(0.05)
        await asyncio.sleep(5)


class DDoSAttacker(Actor):
    """
    🌊 DDoS Attack (Distributed Denial of Service)
    Floods the server with massive requests.
    """
    def __init__(self):
        super().__init__("DDoS-Bot", "Attacker")
        self.client.headers["User-Agent"] = "DDoS-Bot/1.0"
        # Simulate unique attacker IP
        self.client.headers["X-Forwarded-For"] = f"10.0.0.{random.randint(50, 60)}"

    async def perform_action(self):
        logger.warning("🌊 DDoS Attack: Flooding server with requests...")
        tasks = []
        for _ in range(100):
            tasks.append(self.client.get(f"{BASE_URL}/patients"))
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.sleep(3)


class DataExfilAttacker(Actor):
    """
    📤 Data Exfiltration (Yahoo/Equifax style breach)
    Bulk downloading sensitive patient data.
    """
    def __init__(self):
        super().__init__("Exfil-Bot", "Attacker")
        self.client.headers["User-Agent"] = "curl/7.80"
        self.client.headers["X-Forwarded-For"] = f"172.16.0.{random.randint(20, 30)}"

    async def perform_action(self):
        logger.warning("📤 Data Exfiltration: Bulk downloading records...")
        for i in range(40):
            p_id = f"P-{1000 + i}"
            await self.client.get(f"{BASE_URL}/patients/{p_id}")
            await self.client.get(f"{BASE_URL}/patients/{p_id}/vitals")
        await asyncio.sleep(10)


class WormAttacker(Actor):
    """
    🐛 Worm Propagation (Stuxnet/Conficker style)
    Rapidly scanning for vulnerable endpoints.
    """
    def __init__(self):
        super().__init__("Worm-Scanner", "Attacker")
        self.client.headers["User-Agent"] = "Nmap/7.92"
        self.client.headers["X-Forwarded-For"] = f"192.168.50.{random.randint(1, 10)}"

    async def perform_action(self):
        logger.warning("🐛 Worm: Scanning for vulnerable endpoints...")
        endpoints = ["/patients", "/vitals", "/admin", "/config", "/api", "/debug"]
        for _ in range(20):
            endpoint = random.choice(endpoints)
            await self.client.get(f"{BASE_URL}{endpoint}")
            await asyncio.sleep(0.02)
        await asyncio.sleep(8)


# =============================================================================
# TIER 2: WEB & IDENTITY ATTACKS
# =============================================================================

class SQLInjectionAttacker(Actor):
    """
    💉 SQL Injection Attack
    Attempting to inject SQL commands via URL parameters.
    """
    def __init__(self):
        super().__init__("SQLi-Attacker", "Attacker")
        self.client.headers["User-Agent"] = "sqlmap/1.6"
        self.client.headers["X-Forwarded-For"] = f"10.10.10.{random.randint(100, 110)}"
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "'; DROP TABLE patients; --",
            "1 UNION SELECT * FROM users",
            "admin'--",
            "' OR 1=1 #",
        ]

    async def perform_action(self):
        logger.warning("💉 SQL Injection: Attempting injection attacks...")
        for payload in self.payloads:
            # Inject in patient ID parameter
            await self.client.get(f"{BASE_URL}/patients/{payload}")
            await asyncio.sleep(0.2)
        await asyncio.sleep(12)


class XSSAttacker(Actor):
    """
    🔗 XSS (Cross-Site Scripting) Attack
    Injecting malicious scripts via parameters.
    """
    def __init__(self):
        super().__init__("XSS-Attacker", "Attacker")
        self.client.headers["X-Forwarded-For"] = f"192.168.100.{random.randint(200, 210)}"
        self.client.headers["User-Agent"] = "XSSHunter/1.0"
        self.payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert(1)",
            "<svg onload=alert('xss')>",
        ]

    async def perform_action(self):
        logger.warning("🔗 XSS Attack: Injecting malicious scripts...")
        for payload in self.payloads:
            await self.client.get(f"{BASE_URL}/patients/{payload}")
            await asyncio.sleep(0.3)
        await asyncio.sleep(15)


class BruteForceAttacker(Actor):
    """
    🔑 Brute Force Attack
    Attempting multiple failed authentications.
    """
    def __init__(self):
        super().__init__("BruteForce-Bot", "Attacker")
        self.client.headers["User-Agent"] = "Hydra/9.3"

    async def perform_action(self):
        logger.warning("🔑 Brute Force: Attempting unauthorized access...")
        for _ in range(25):
            # Try non-existent patient IDs (will get 404)
            fake_id = f"P-{random.randint(5000, 9999)}"
            await self.client.get(f"{BASE_URL}/patients/{fake_id}")
            await asyncio.sleep(0.08)
        await asyncio.sleep(8)


class DirectoryTraversalAttacker(Actor):
    """
    📂 Directory Traversal Attack
    Attempting to access files outside web root.
    """
    def __init__(self):
        super().__init__("DirTraversal-Bot", "Attacker")
        self.client.headers["User-Agent"] = "DirBuster/1.0"
        self.payloads = [
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
        ]

    async def perform_action(self):
        logger.warning("📂 Directory Traversal: Attempting path escape...")
        for payload in self.payloads:
            await self.client.get(f"{BASE_URL}/files/{payload}")
            await asyncio.sleep(0.5)
        await asyncio.sleep(20)


class DataScrapingAttacker(Actor):
    """
    🕷️ Data Scraping Attack
    Systematically harvesting all patient data.
    """
    def __init__(self):
        super().__init__("Scraper-Bot", "Attacker")
        self.client.headers["User-Agent"] = "Scrapy/2.6"
        self.current_id = 1000

    async def perform_action(self):
        logger.warning("🕷️ Scraping: Harvesting patient data systematically...")
        for _ in range(25):
            patient_id = f"P-{self.current_id}"
            await self.client.get(f"{BASE_URL}/patients/{patient_id}")
            await self.client.get(f"{BASE_URL}/patients/{patient_id}/vitals")
            self.current_id += 1
            if self.current_id > 1050:
                self.current_id = 1000
            await asyncio.sleep(0.15)
        await asyncio.sleep(7)


class CryptojackingSimulator(Actor):
    """
    ⛏️ Cryptojacking Simulation
    Simulating mining behavior with heavy requests.
    """
    def __init__(self):
        super().__init__("Miner-Process", "Malware")
        self.client.headers["User-Agent"] = "XMRig/6.18"

    async def perform_action(self):
        logger.warning("⛏️ Cryptojacking: Simulating mining activity...")
        # Heavy continuous requests simulating CPU load
        for _ in range(50):
            await self.client.get(f"{BASE_URL}/patients")
            await asyncio.sleep(0.01)
        await asyncio.sleep(5)


# =============================================================================
# MAIN SIMULATION
# =============================================================================

async def main():
    import argparse
    parser = argparse.ArgumentParser(description='Healthcare Traffic Simulator')
    parser.add_argument('--mode', type=str, default='all', choices=['all', 'normal', 'attack'],
                        help='Traffic mode: "normal" (benign only), "attack" (attacks only), or "all" (both)')
    parser.add_argument('--delay', type=float, default=0.0, help='Initial delay in seconds')
    args = parser.parse_args()

    if args.delay > 0:
        print(f"Waiting {args.delay} seconds before starting...")
        await asyncio.sleep(args.delay)

    print("=" * 70)
    print(f"🏥 HEALTHCARE TRAFFIC SIMULATOR - MODE: {args.mode.upper()}")
    print("=" * 70)
    
    actors: List[Actor] = []
    
    # Normal hospital staff (3 Nurses)
    if args.mode in ['all', 'normal']:
        print("✅ Adding Normal Traffic (Nurses)...")
        for i in range(3):
            actors.append(Nurse(f"Nurse-{i+1}", "Nurse"))
    
    # ATTACKERS
    if args.mode in ['all', 'attack']:
        print("⚠️ Adding Attack Traffic...")
        print("   TIER 1 (System): BOLA, DDoS, Data Exfil, Worm")
        print("   TIER 2 (Web):    SQLi, XSS, Brute Force, Dir Traversal")
        
        # TIER 1: System & Network Attacks
        actors.append(BOLAAttacker())
        actors.append(DDoSAttacker())
        actors.append(DataExfilAttacker())
        actors.append(WormAttacker())
        
        # TIER 2: Web & Identity Attacks
        actors.append(SQLInjectionAttacker())
        actors.append(XSSAttacker())
        actors.append(BruteForceAttacker())
        actors.append(DirectoryTraversalAttacker())
        
        # Additional Attacks
        actors.append(DataScrapingAttacker())
        actors.append(CryptojackingSimulator())

    print("\n🎭 ACTORS STARTED:")
    print("-" * 70)
    for actor in actors:
        emoji = "🏥" if actor.role == "Nurse" else "💀" if actor.role == "Attacker" else "🦠"
        print(f"   {emoji} {actor.name:25} [{actor.role}]")
    print("-" * 70)
    print("\n🚀 Simulation running... (Ctrl+C to stop)\n")
    
    await asyncio.gather(*(actor.run() for actor in actors))


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
