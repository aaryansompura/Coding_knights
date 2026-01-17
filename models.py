from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field

class Vitals(BaseModel):
    id: str
    patient_id: str
    timestamp: datetime
    heart_rate: int = Field(..., ge=0, le=300, description="BPM")
    blood_pressure_sys: int = Field(..., ge=0, le=300)
    blood_pressure_dia: int = Field(..., ge=0, le=300)
    oxygen_saturation: int = Field(..., ge=0, le=100)
    body_temperature: float = Field(..., ge=30.0, le=45.0)

class Diagnosis(BaseModel):
    code: str
    description: str
    diagnosed_date: datetime

class Patient(BaseModel):
    id: str
    name: str
    dob: str
    gender: str
    blood_type: str
    allergies: List[str] = []
    diagnoses: List[Diagnosis] = []
    is_vip: bool = False # Sensitive flag for authorized access only

class AccessLog(BaseModel):
    timestamp: datetime
    user_id: str
    role: str # Doctor, Nurse, Admin, etc.
    action: str # READ, WRITE, EXPORT
    resource: str
    resource_id: Optional[str] = None
    ip_address: str
    status: str
