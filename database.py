import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, List
from .models import Patient, Vitals, Diagnosis

# Simple in-memory storage simulating a Hospital Database
patients_db: Dict[str, Patient] = {}
vitals_db: Dict[str, List[Vitals]] = {}

def generate_synthetic_data(count: int = 50):
    """Generates synthetic patient data for the simulation."""
    first_names = ["James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", "William", "Elizabeth"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez"]
    conditions = [
        ("E11.9", "Type 2 diabetes mellitus without complications"),
        ("I10", "Essential (primary) hypertension"),
        ("J45.909", "Unspecified asthma, uncomplicated"),
        ("M54.5", "Low back pain")
    ]

    for i in range(count):
        p_id = f"P-{1000+i}"
        
        # Random basics
        name = f"{random.choice(first_names)} {random.choice(last_names)}"
        
        # Clinical data
        diag = []
        if random.random() < 0.3:
            c = random.choice(conditions)
            diag.append(Diagnosis(
                code=c[0], 
                description=c[1], 
                diagnosed_date=datetime.now() - timedelta(days=random.randint(10, 1000))
            ))

        patient = Patient(
            id=p_id,
            name=name,
            dob=(datetime.now() - timedelta(days=random.randint(7000, 30000))).strftime("%Y-%m-%d"),
            gender=random.choice(["Male", "Female"]),
            blood_type=random.choice(["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]),
            allergies=random.sample(["Peanuts", "Penicillin", "Latex", "Dust"], k=random.randint(0, 2)),
            diagnoses=diag,
            is_vip=random.random() < 0.05 # 5% are VIPs (Politicians/Celebs) - High Risk
        )
        
        patients_db[p_id] = patient
        vitals_db[p_id] = []

        # Generate some history vitals
        for d in range(5):
            vitals_db[p_id].append(Vitals(
                id=str(uuid.uuid4()),
                patient_id=p_id,
                timestamp=datetime.now() - timedelta(days=d),
                heart_rate=random.randint(60, 100),
                blood_pressure_sys=random.randint(110, 140),
                blood_pressure_dia=random.randint(70, 90),
                oxygen_saturation=random.randint(95, 100),
                body_temperature=round(random.uniform(36.5, 37.2), 1)
            ))

# Initialize on module load (for simple proto)
generate_synthetic_data()
