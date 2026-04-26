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

class MatchedDetection(BaseModel):
    """Represents a matched detection rule from Sigma or Elastic repositories."""
    title: str = Field(..., description="Detection rule title")
    description: str = Field(..., description="What this detection identifies")
    repository: str = Field(..., description="Source repository (SigmaHQ/sigma or elastic/detection-rules)")
    url: str = Field(..., description="GitHub URL to the rule")
    file_path: str = Field(..., description="Relative path in repository")
    level: Optional[str] = Field(default=None, description="Severity level")
    matched_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques that matched")
    matched_keywords: List[str] = Field(default_factory=list, description="Keywords that matched")
    tags: List[str] = Field(default_factory=list, description="Rule tags")

class ThreatReport(BaseModel):
    title: str
    summary: str = Field(..., description="A 3-4 sentence executive summary of the threat.")
    attack_chain: List[AttackStep] = Field(..., description="Sequential steps of the intrusion.")
    detections: List[MatchedDetection] = Field(default_factory=list, description="Matched detection rules from repositories")
    iocs: List[IOC]