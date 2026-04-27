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

class AtomicTest(BaseModel):
    """Represents an Atomic Red Team test with relevance context."""
    test_number: int
    name: str
    description: str
    supported_platforms: List[str]
    executor: str
    relevance_score: Optional[float] = None  # How relevant to the specific attack (0-1)
    relevance_reason: Optional[str] = None  # WHY this test is relevant to the attack
    custom_test_suggestion: Optional[str] = None  # Custom test if no atomic test matches well

class TechniqueCoverage(BaseModel):
    """Coverage analysis for a single technique."""
    technique_id: str
    technique_name: str
    detection_count: int
    atomic_test_count: int
    detection_score: int
    coverage_grade: str
    is_gap: bool

class DetectionGap(BaseModel):
    """Represents a critical detection gap."""
    technique_id: str
    technique_name: str
    description: str
    priority: str
    has_atomic_tests: bool
    recommendation: str

class SuggestedSigmaRule(BaseModel):
    """AI-generated Sigma rule suggestion with attack context."""
    technique_id: str
    technique_name: str
    sigma_rule: str
    rationale: str  # WHY this detection is suggested based on the specific attack
    observed_in_attack: str  # WHERE in the attack chain this pattern was seen
    specific_indicators: List[str]  # Specific IOCs/patterns from the report
    data_sources: str
    implementation_notes: str
    tuning_recommendations: str
    expected_fp_rate: str
    confidence: str
    requires_validation: bool

class HuntingQuery(BaseModel):
    """Context-aware threat hunting query."""
    technique_id: str
    technique_name: str
    query_type: str  # SPLUNK, KQL, EQL, SQL
    query: str
    rationale: str  # WHY hunt for this based on the specific attack
    observed_in_attack: str  # WHERE in the attack chain to focus
    what_to_look_for: str
    expected_fp_rate: str
    hunting_frequency: str
    baseline_notes: str

class BehavioralPattern(BaseModel):
    """Identified behavioral pattern from attack chain."""
    pattern_type: str  # process_chain, file_ops, network, temporal, lolbin
    sequence: str
    detection_opportunity: str
    data_sources: str
    example_logic: str

class ThreatReport(BaseModel):
    title: str
    summary: str = Field(..., description="A 3-4 sentence executive summary of the threat.")
    attack_chain: List[AttackStep] = Field(..., description="Sequential steps of the intrusion.")
    detections: List[MatchedDetection] = Field(default_factory=list, description="Matched detection rules from repositories")
    iocs: List[IOC]
    atomic_tests: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Atomic Red Team tests by technique")
    coverage_summary: Optional[Dict[str, Any]] = Field(default=None, description="Detection coverage analysis summary")
    critical_gaps: List[DetectionGap] = Field(default_factory=list, description="Prioritized detection gaps")
    suggested_sigma_rules: List[SuggestedSigmaRule] = Field(default_factory=list, description="AI-generated Sigma rules for gaps")
    hunting_queries: List[HuntingQuery] = Field(default_factory=list, description="Threat hunting queries")
    behavioral_patterns: List[BehavioralPattern] = Field(default_factory=list, description="Identified behavioral patterns")