from fastapi import APIRouter, HTTPException, Request, Depends
from typing import List
from ..models import Patient, Vitals
from ..database import patients_db, vitals_db
import random
import time

router = APIRouter()

# --- Middleware / Simulation Hooks ---
# In a real app, this would be an auth middleware. 
# Here we simulate extracting user info' from headers for the Sentinel.

def simulate_latency():
    """Simulate legacy hospital system latency."""
    if random.random() < 0.1:
        time.sleep(0.5)

@router.get("/patients", response_model=List[Patient])
async def get_patients(request: Request, skip: int = 0, limit: int = 10):
    """
    Get a list of patients. 
    Standard endpoint.
    """
    simulate_latency()
    all_patients = list(patients_db.values())
    return all_patients[skip : skip + limit]

@router.get("/patients/{patient_id}", response_model=Patient)
async def get_patient_detail(patient_id: str, request: Request):
    """
    Get specific patient details.
    VULNERABILITY: BOLA (Broken Object Level Authorization) simulation.
    The system 'checks' permissions but we will allow our simulator to exploit this.
    """
    simulate_latency()
    patient = patients_db.get(patient_id)
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    # In a real secure system: Check if request.user has access to patient_id
    # We will log this access for the Sentinel to analyze.
    return patient

@router.get("/patients/{patient_id}/vitals", response_model=List[Vitals])
async def get_patient_vitals(patient_id: str):
    """
    Get patient vitals history.
    """
    if patient_id not in patients_db:
        raise HTTPException(status_code=404, detail="Patient not found")
    return vitals_db.get(patient_id, [])
