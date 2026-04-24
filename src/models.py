from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class IOC(BaseModel):
    value: str = Field(..., description="The actual indicator (IP, Hash, Domain)")
    type: str = Field(..., description="Category: e.g., 'sha256', 'ipv4', 'file_path'")
    context: Optional[str] = Field(default=None, description="What was this IOC used for? (e.g., C2, Exfiltration)")

class AttackStep(BaseModel):
    technique_id: str = Field(..., description="MITRE ATT&CK ID (e.g., T1059.003)")
    technique_name: str = Field(..., description="The name of the technique")
    description: str = Field(..., description="A brief narrative of what the actor did here.")

class DetectionLogic(BaseModel):
    title: str = Field(..., description="A short name for the detection")
    description: str = Field(..., description="Description of what this detection identifies")
    status: str = Field(default="experimental", description="Sigma rule status: stable, test, or experimental")
    logsource: Dict[str, Any] = Field(..., description="Sigma logsource definition with category, product, and/or service")
    detection: Dict[str, Any] = Field(..., description="Sigma detection logic with selection and condition")
    falsepositives: List[str] = Field(default_factory=list, description="Known false positive scenarios")
    level: str = Field(..., description="Sigma level: informational, low, medium, high, or critical")
    tags: List[str] = Field(default_factory=list, description="MITRE ATT&CK tags and other relevant tags")

class ThreatReport(BaseModel):
    title: str
    summary: str = Field(..., description="A 3-4 sentence executive summary of the threat.")
    attack_chain: List[AttackStep] = Field(..., description="Sequential steps of the intrusion.")
    detections: List[DetectionLogic]
    iocs: List[IOC]