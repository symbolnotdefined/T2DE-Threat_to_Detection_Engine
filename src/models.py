from typing import List, Optional
from pydantic import BaseModel, Field

class IOC(BaseModel):
    value: str = Field(..., description="The actual indicator (IP, Hash, Domain)")
    type: str = Field(..., description="Category: e.g., 'sha256', 'ipv4', 'file_path'")
    context: Optional[str] = Field(None, description="What was this IOC used for? (e.g., C2, Exfiltration)")

class AttackStep(BaseModel):
    technique_id: str = Field(..., description="MITRE ATT&CK ID (e.g., T1059.003)")
    technique_name: str = Field(..., description="The name of the technique")
    description: str = Field(..., description="A brief narrative of what the actor did here.")

class DetectionLogic(BaseModel):
    title: str = Field(..., description="A short name for the detection")
    behavior: str = Field(..., description="Description of the behavioral logic to alert on")
    severity: str = Field(..., description="Low, Medium, High, or Critical")
    pseudo_query: str = Field(..., description="A generic query or logic flow for SOC analysts")

class ThreatReport(BaseModel):
    title: str
    summary: str = Field(..., description="A 3-4 sentence executive summary of the threat.")
    attack_chain: List[AttackStep] = Field(..., description="Sequential steps of the intrusion.")
    detections: List[DetectionLogic]
    iocs: List[IOC]