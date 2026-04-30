# T2DE Code Explanation

## Table of Contents
1. [Overview](#overview)
2. [Core Components](#core-components)
3. [Data Models](#data-models)
4. [Processing Pipeline](#processing-pipeline)
5. [Context-Aware Detection Generation](#context-aware-detection-generation)
6. [Code Examples](#code-examples)

---

## Overview

T2DE (Threat-to-Detection Engine) transforms threat intelligence reports into actionable detection logic using AI. The system is built with a modular architecture where each component has a specific responsibility.

### Technology Stack
- **Python 3.x**: Core language
- **LangChain**: LLM orchestration
- **Pydantic**: Data validation and modeling
- **Git**: Repository management for detection rules
- **Markdown**: Output format

---

## Core Components

### 1. main.py - Entry Point

**Purpose**: Command-line interface and orchestration

```python
# Key responsibilities:
- Parse command-line arguments (--input, --output)
- Initialize IntelParser
- Handle file/URL input
- Write output to markdown file
```

**Flow**:
```
User Command → Parse Args → Read Input → IntelParser.parse() → Write Output
```

---

### 2. src/parser.py - IntelParser

**Purpose**: Main orchestrator that coordinates all analysis steps

#### Key Methods:

##### `__init__()`
```python
def __init__(self):
    self.llm = self._initialize_llm()  # Initialize LLM provider
    self.parser = PydanticOutputParser(pydantic_object=ThreatReport)
    self.detection_matcher = DetectionMatcher()
    self.coverage_analyzer = CoverageAnalyzer()
    self.detection_suggester = DetectionSuggester()
```

**What it does**: Sets up all required components based on environment configuration.

##### `_initialize_llm()`
```python
def _initialize_llm(self):
    provider = os.getenv("LLM_PROVIDER", "ollama").lower()
    
    if provider == "anthropic":
        return ChatAnthropic(model_name="claude-opus-4", ...)
    elif provider == "openai":
        return ChatOpenAI(model="gpt-4", ...)
    elif provider == "ollama":
        return ChatOllama(model="llama3.1", ...)
```

**What it does**: Creates the appropriate LLM client based on environment variables. Supports multiple providers for flexibility.

##### `parse(intel_text: str) -> ThreatReport`
```python
def parse(self, intel_text: str) -> ThreatReport:
    # Step 1: Extract structured threat intelligence
    result = self._extract_threat_intel(intel_text)
    
    # Step 2: Match existing detections
    detections = self.detection_matcher.match_detections(result.attack_chain)
    
    # Step 3: Analyze coverage
    coverage = self.coverage_analyzer.analyze_coverage(...)
    
    # Step 4: Generate AI suggestions for gaps
    suggestions = self.detection_suggester.generate_suggestions_for_gaps(...)
    
    return result
```

**What it does**: Orchestrates the entire analysis pipeline in sequence.

---

### 3. src/models.py - Data Models

**Purpose**: Define type-safe data structures using Pydantic

#### Key Models:

##### IOC (Indicator of Compromise)
```python
class IOC(BaseModel):
    value: str          # The actual indicator (IP, hash, domain)
    type: str           # Category (sha256, ipv4, file_path)
    context: Optional[str]  # What was this used for?
```

**Example**:
```python
IOC(
    value="192.168.1.100",
    type="ipv4",
    context="C2 server for data exfiltration"
)
```

##### AttackStep
```python
class AttackStep(BaseModel):
    technique_id: str       # MITRE ATT&CK ID (e.g., T1059.003)
    technique_name: str     # Name of the technique
    description: str        # What the actor did
```

**Example**:
```python
AttackStep(
    technique_id="T1059.003",
    technique_name="Command and Scripting Interpreter: Windows Command Shell",
    description="Attacker used PowerShell to download malicious payload"
)
```

##### SuggestedSigmaRule (Context-Aware)
```python
class SuggestedSigmaRule(BaseModel):
    technique_id: str
    technique_name: str
    sigma_rule: str                    # YAML rule
    rationale: str                     # WHY this detection?
    observed_in_attack: str            # WHERE in attack chain?
    specific_indicators: List[str]     # Actual indicators from attack
    data_sources: str
    implementation_notes: str
    tuning_recommendations: str
    expected_fp_rate: str
    confidence: str
    requires_validation: bool
```

**What makes it context-aware**: The `rationale`, `observed_in_attack`, and `specific_indicators` fields tie the detection directly to the specific attack being analyzed.

---

### 4. src/detection_matcher.py - DetectionMatcher

**Purpose**: Search detection repositories for existing rules

#### Key Methods:

##### `setup_repositories()`
```python
def setup_repositories(self):
    # Clone or update Sigma repository
    if not os.path.exists(self.sigma_repo_path):
        git.Repo.clone_from(self.sigma_repo_url, self.sigma_repo_path)
    
    # Clone or update Elastic repository
    # Clone or update Atomic Red Team repository
```

**What it does**: Ensures local copies of detection repositories are available and up-to-date.

##### `match_detections(attack_chain: List[AttackStep])`
```python
def match_detections(self, attack_chain):
    matched_detections = []
    
    for step in attack_chain:
        # Search Sigma rules by technique ID
        sigma_matches = self._search_sigma_rules(step.technique_id)
        
        # Search Elastic rules by technique ID
        elastic_matches = self._search_elastic_rules(step.technique_id)
        
        matched_detections.extend(sigma_matches + elastic_matches)
    
    return matched_detections
```

**What it does**: For each attack step, searches both Sigma and Elastic repositories for matching detection rules.

---

### 5. src/coverage_analyzer.py - CoverageAnalyzer

**Purpose**: Quantify detection coverage and identify gaps

#### Key Methods:

##### `analyze_coverage(attack_chain, detections, atomic_tests)`
```python
def analyze_coverage(self, attack_chain, detections, atomic_tests):
    coverage_by_technique = {}
    
    for step in attack_chain:
        # Count detections for this technique
        detection_count = len([d for d in detections 
                              if step.technique_id in d.matched_techniques])
        
        # Count atomic tests for this technique
        test_count = len([t for t in atomic_tests 
                         if t.technique_id == step.technique_id])
        
        # Calculate score (0-100)
        score = self._calculate_detection_score(
            detection_count, test_count
        )
        
        coverage_by_technique[step.technique_id] = {
            'detection_count': detection_count,
            'test_count': test_count,
            'score': score,
            'grade': self._score_to_grade(score)
        }
    
    return coverage_by_technique
```

**What it does**: Analyzes how well each technique is covered by existing detections and tests.

##### `_calculate_detection_score(detection_count, test_count)`
```python
def _calculate_detection_score(self, detection_count, test_count):
    # Base score from detection count (0-60 points)
    detection_score = min(detection_count * 15, 60)
    
    # Bonus for test coverage (0-20 points)
    test_score = min(test_count * 10, 20)
    
    # Bonus for diversity (0-20 points)
    diversity_score = min(detection_count * 5, 20) if detection_count > 1 else 0
    
    return detection_score + test_score + diversity_score
```

**What it does**: Calculates a 0-100 score based on multiple factors:
- Number of detections (more is better)
- Test coverage (can we validate?)
- Detection diversity (multiple approaches)

##### `identify_critical_gaps(coverage_analysis, attack_chain)`
```python
def identify_critical_gaps(self, coverage_analysis, attack_chain):
    gaps = []
    
    for step in attack_chain:
        coverage = coverage_analysis.get(step.technique_id, {})
        
        if coverage.get('detection_count', 0) == 0:
            # No detections = CRITICAL gap
            priority = 'CRITICAL'
        elif coverage.get('score', 0) < 40:
            # Low score = HIGH priority gap
            priority = 'HIGH'
        else:
            continue
        
        gaps.append({
            'technique_id': step.technique_id,
            'technique_name': step.technique_name,
            'priority': priority,
            'recommendation': f"Implement detection for {step.technique_name}"
        })
    
    return sorted(gaps, key=lambda x: x['priority'])
```

**What it does**: Identifies techniques with no or poor detection coverage and prioritizes them.

---

### 6. src/detection_suggester.py - DetectionSuggester

**Purpose**: Generate context-aware detection suggestions using AI

This is the most complex component. Let's break it down:

#### Helper Methods (Context Building):

##### `_build_attack_context(gap, attack_chain)`
```python
def _build_attack_context(self, gap, attack_chain):
    # Find steps related to this gap's technique
    related_steps = [
        step for step in attack_chain 
        if gap.technique_id in step.technique_id
    ]
    
    context_parts = []
    
    # Add how the technique was used
    if related_steps:
        context_parts.append("**How this technique was used:**")
        for step in related_steps:
            context_parts.append(f"- {step.description}")
    
    # Add surrounding context (before/after steps)
    if related_steps and attack_chain:
        first_occurrence = attack_chain.index(related_steps[0])
        
        # Previous step
        if first_occurrence > 0:
            prev = attack_chain[first_occurrence - 1]
            context_parts.append(f"→ Previous: {prev.technique_name}")
        
        # Current step
        context_parts.append(f"→ **Current: {gap.technique_name}** (GAP)")
        
        # Next step
        if first_occurrence < len(attack_chain) - 1:
            next_step = attack_chain[first_occurrence + 1]
            context_parts.append(f"→ Next: {next_step.technique_name}")
    
    return "\n".join(context_parts)
```

**What it does**: Builds a narrative showing:
1. How the technique was actually used in this attack
2. What happened before (attack chain context)
3. What happened after (attack chain context)

**Why it matters**: This context helps the AI generate detections specific to this attack, not generic technique patterns.

##### `_extract_specific_indicators(gap, attack_chain, iocs)`
```python
def _extract_specific_indicators(self, gap, attack_chain, iocs):
    indicators = []
    
    # Find related attack steps
    related_steps = [
        step for step in attack_chain 
        if gap.technique_id in step.technique_id
    ]
    
    # Extract patterns from descriptions
    for step in related_steps:
        desc = step.description.lower()
        
        if 'powershell' in desc or 'cmd' in desc:
            indicators.append(f"- Process/Command: {step.description}")
        elif 'file' in desc or 'directory' in desc:
            indicators.append(f"- File Operation: {step.description}")
        elif 'network' in desc or 'connection' in desc:
            indicators.append(f"- Network Activity: {step.description}")
    
    # Add relevant IOCs
    if iocs:
        for ioc in iocs[:5]:
            indicators.append(f"- IOC ({ioc.type}): {ioc.value}")
    
    return "\n".join(indicators)
```

**What it does**: Extracts specific, observable indicators from the attack:
- Process names and commands
- File operations
- Network activity
- IOCs (IPs, hashes, domains)

**Why it matters**: These specific indicators are used in the generated detection rules, making them tailored to this attack.

#### Main Generation Methods:

##### `generate_sigma_rule(gap, attack_chain, iocs)`
```python
def generate_sigma_rule(self, gap, attack_chain, iocs):
    # Build context
    attack_context = self._build_attack_context(gap, attack_chain)
    specific_indicators = self._extract_specific_indicators(gap, attack_chain, iocs)
    
    # Create context-aware prompt
    prompt = ChatPromptTemplate.from_template("""
    Generate a CONTEXT-AWARE Sigma rule based on this SPECIFIC attack:
    
    **Technique:** {technique_id} - {technique_name}
    
    **SPECIFIC ATTACK CONTEXT:**
    {attack_context}
    
    **OBSERVED INDICATORS:**
    {specific_indicators}
    
    IMPORTANT: Your detection should target the SPECIFIC behaviors 
    observed in this attack, not generic technique patterns.
    
    Provide:
    - RATIONALE: WHY this detection is needed
    - OBSERVED_IN_ATTACK: WHERE this pattern appears
    - SPECIFIC_INDICATORS: Actual indicators from the attack
    - SIGMA_RULE: The YAML rule
    """)
    
    # Invoke LLM
    response = self.llm.invoke(prompt.format(...))
    
    # Parse response
    rationale = self._extract_section(content, "RATIONALE:", "OBSERVED_IN_ATTACK:")
    observed = self._extract_section(content, "OBSERVED_IN_ATTACK:", "SPECIFIC_INDICATORS:")
    indicators = self._extract_section(content, "SPECIFIC_INDICATORS:", "SIGMA_RULE:")
    sigma_rule = self._extract_section(content, "SIGMA_RULE:", "DATA_SOURCES:")
    
    return {
        'technique_id': gap.technique_id,
        'sigma_rule': sigma_rule,
        'rationale': rationale,
        'observed_in_attack': observed,
        'specific_indicators': indicators,
        ...
    }
```

**What it does**:
1. Builds attack-specific context
2. Extracts specific indicators
3. Creates a detailed prompt with context
4. Invokes LLM to generate detection
5. Parses and structures the response

**Key Innovation**: The prompt explicitly instructs the AI to generate detections for THIS SPECIFIC ATTACK, not generic technique patterns.

##### `generate_hunting_queries(gap, attack_chain, query_types)`
```python
def generate_hunting_queries(self, gap, attack_chain, query_types):
    queries = []
    attack_context = self._build_attack_context(gap, attack_chain)
    
    for query_type in query_types:  # e.g., ['splunk', 'kql']
        prompt = ChatPromptTemplate.from_template("""
        Generate a CONTEXT-AWARE {query_type} hunting query 
        based on this SPECIFIC attack:
        
        **SPECIFIC ATTACK CONTEXT:**
        {attack_context}
        
        Your query should hunt for the SPECIFIC behaviors observed.
        
        Provide:
        - RATIONALE: WHY hunt for this
        - OBSERVED_IN_ATTACK: WHERE to focus
        - QUERY: The actual query
        """)
        
        response = self.llm.invoke(prompt.format(...))
        
        # Parse and structure response
        queries.append({
            'query_type': query_type.upper(),
            'rationale': rationale,
            'observed_in_attack': observed,
            'query': query,
            ...
        })
    
    return queries
```

**What it does**: Similar to Sigma rule generation, but creates hunting queries (Splunk, KQL, etc.) tailored to the specific attack.

---

### 7. src/renderer.py - ReportRenderer

**Purpose**: Generate human-readable markdown reports

#### Key Method:

##### `render(report: ThreatReport) -> str`
```python
def render(self, report):
    md = "# Threat Intelligence Analysis\n\n"
    
    # Executive Summary
    md += "## Executive Summary\n\n"
    md += f"**Threat:** {report.title}\n"
    md += f"**Techniques:** {len(report.attack_chain)}\n"
    md += f"**IOCs:** {len(report.iocs)}\n"
    
    # Attack Chain
    md += "## Attack Chain\n\n"
    for i, step in enumerate(report.attack_chain, 1):
        md += f"{i}. **{step.technique_name}** ({step.technique_id})\n"
        md += f"   {step.description}\n\n"
    
    # IOCs
    md += "## Indicators of Compromise\n\n"
    for ioc in report.iocs:
        md += f"- **{ioc.type}**: `{ioc.value}`\n"
        if ioc.context:
            md += f"  *{ioc.context}*\n"
    
    # Matched Detections
    md += "## Matched Detections\n\n"
    for detection in report.detections:
        md += f"### {detection.title}\n"
        md += f"**Repository:** {detection.repository}\n"
        md += f"**Level:** {detection.level}\n"
        md += f"[View Rule]({detection.url})\n\n"
    
    # Coverage Analysis
    md += "## Detection Coverage Analysis\n\n"
    md += f"**Overall Score:** {report.coverage_summary['overall_score']}/100\n"
    md += f"**Grade:** {report.coverage_summary['overall_grade']}\n\n"
    
    # Critical Gaps
    md += "## Critical Detection Gaps\n\n"
    for gap in report.critical_gaps:
        md += f"### {gap.priority}: {gap.technique_name}\n"
        md += f"{gap.recommendation}\n\n"
    
    # AI-Generated Sigma Rules (Context-Aware)
    md += "## 🤖 AI-Generated Sigma Rules\n\n"
    for rule in report.suggested_sigma_rules:
        md += f"### {rule.technique_id} - {rule.technique_name}\n\n"
        
        # Context-aware sections
        md += "#### 💡 Why This Detection?\n"
        md += f"{rule.rationale}\n\n"
        
        md += "#### 🔍 Observed in Attack\n"
        md += f"{rule.observed_in_attack}\n\n"
        
        md += "#### 🎯 Specific Indicators\n"
        for indicator in rule.specific_indicators:
            md += f"- {indicator}\n"
        md += "\n"
        
        md += "#### Sigma Rule\n"
        md += "```yaml\n"
        md += rule.sigma_rule
        md += "\n```\n\n"
    
    # Hunting Queries (Context-Aware)
    md += "## 🎯 Threat Hunting Queries\n\n"
    for query in report.hunting_queries:
        md += f"### {query.technique_id} - {query.technique_name}\n\n"
        
        md += "#### 💡 Why Hunt for This?\n"
        md += f"{query.rationale}\n\n"
        
        md += "#### 🔍 Focus Area\n"
        md += f"{query.observed_in_attack}\n\n"
        
        md += "#### Query\n"
        md += f"```{query.query_type.lower()}\n"
        md += query.query
        md += "\n```\n\n"
    
    return md
```

**What it does**: Transforms the structured ThreatReport object into a comprehensive, readable markdown document with all analysis results.

---

## Processing Pipeline

### Complete Flow with Example:

**Input**: Threat report about ransomware attack

```
1. main.py receives input
   ↓
2. IntelParser.parse() called
   ↓
3. LLM extracts structured data:
   - Attack Chain: [Initial Access, Execution, Defense Evasion, ...]
   - IOCs: [192.168.1.100, malware.exe, evil.com]
   - Techniques: [T1566.001, T1059.003, T1055, ...]
   ↓
4. DetectionMatcher searches repositories:
   - Found 5 Sigma rules for T1566.001
   - Found 3 Elastic rules for T1059.003
   - Found 2 Atomic tests for T1055
   ↓
5. CoverageAnalyzer calculates scores:
   - T1566.001: Score 75/100, Grade B (good coverage)
   - T1059.003: Score 45/100, Grade D (poor coverage)
   - T1055: Score 0/100, Grade F (NO COVERAGE - GAP!)
   ↓
6. DetectionSuggester generates for gaps:
   
   For T1055 (Process Injection):
   
   a) Build context:
      "Attacker used process injection to hide malicious code
       in legitimate svchost.exe process after gaining initial
       access via phishing email."
   
   b) Extract indicators:
      - Process: svchost.exe with suspicious parent
      - Memory: Unusual memory allocation patterns
      - IOC: malware.exe (SHA256: abc123...)
   
   c) Generate Sigma rule:
      ```yaml
      title: Suspicious Process Injection into svchost.exe
      description: Detects process injection observed in [Attack Name]
      detection:
        selection:
          EventID: 10
          TargetImage: '*\svchost.exe'
          SourceImage: '*\malware.exe'
      ```
      
      Rationale: "This detection targets the specific process
      injection technique where malware.exe injected code into
      svchost.exe, as observed in step 3 of the attack chain."
   
   d) Generate hunting query:
      ```splunk
      index=windows EventCode=10
      | where TargetImage LIKE "%svchost.exe"
      | where SourceImage NOT IN (known_good_processes)
      | stats count by SourceImage, TargetImage, Computer
      ```
      
      Rationale: "Hunt for similar injection patterns where
      unexpected processes inject into svchost.exe, focusing
      on the timeframe around initial access."
   ↓
7. ReportRenderer generates markdown:
   - Executive summary
   - Attack visualization
   - Matched detections
   - Coverage analysis
   - AI-generated suggestions with context
   ↓
8. Output written to file
```

---

## Context-Aware Detection Generation

### The Problem We Solved:

**Before (Generic)**:
```
Input: T1059.003 (PowerShell)
Output: Generic PowerShell detection rule
Issue: Doesn't match the specific attack behaviors
```

**After (Context-Aware)**:
```
Input: 
- Technique: T1059.003
- Attack Context: "Attacker used PowerShell with -EncodedCommand 
  to download payload from compromised-site.com"
- Indicators: powershell.exe, -enc, compromised-site.com

Output: Detection rule that specifically looks for:
- PowerShell with -EncodedCommand parameter
- Network connections to suspicious domains
- Download activity to %TEMP% directory

Rationale: "This detection targets the specific PowerShell 
download cradle observed in step 2 of the attack, where the
attacker used encoded commands to evade detection."
```

### How It Works:

1. **Context Building** (`_build_attack_context`):
   - Finds where the technique appears in the attack chain
   - Extracts the actual description of what happened
   - Maps the before/after steps for context

2. **Indicator Extraction** (`_extract_specific_indicators`):
   - Parses attack step descriptions for patterns
   - Identifies processes, files, network activity
   - Includes relevant IOCs

3. **Prompt Engineering**:
   - Explicitly instructs AI to focus on THIS attack
   - Provides full context and indicators
   - Requests rationale and attack chain mapping

4. **Structured Output**:
   - Parses AI response into structured fields
   - Validates with Pydantic models
   - Ensures all required context is captured

### Benefits:

✅ **Relevant**: Detections match the actual attack
✅ **Explainable**: Clear rationale for each detection
✅ **Actionable**: Specific indicators to look for
✅ **Testable**: Can validate against the attack description
✅ **Tunable**: Context helps with false positive reduction

---

## Code Examples

### Example 1: Running the Tool

```bash
# Analyze a local threat report
python main.py --input data/raw/ransomware_report.txt --output analysis.md

# Analyze from URL
python main.py --input https://example.com/threat-report --output analysis.md
```

### Example 2: Using Different LLM Providers

```bash
# .env file for Ollama (free, local)
LLM_PROVIDER=ollama
OLLAMA_MODEL=llama3.1
OLLAMA_BASE_URL=http://localhost:11434

# .env file for Claude (API)
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...

# .env file for GPT (API)
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
```

### Example 3: Programmatic Usage

```python
from src.parser import IntelParser

# Initialize parser
parser = IntelParser()

# Parse threat report
threat_report = """
A sophisticated ransomware campaign was observed...
The attackers gained initial access via phishing...
They used PowerShell to download additional payloads...
"""

# Analyze
result = parser.parse(threat_report)

# Access results
print(f"Attack Chain: {len(result.attack_chain)} steps")
print(f"IOCs: {len(result.iocs)}")
print(f"Coverage Score: {result.coverage_summary['overall_score']}/100")
print(f"Critical Gaps: {len(result.critical_gaps)}")

# Access AI suggestions
for rule in result.suggested_sigma_rules:
    print(f"\nSuggested Rule: {rule.technique_name}")
    print(f"Rationale: {rule.rationale}")
    print(f"Observed: {rule.observed_in_attack}")
```

### Example 4: Extending with New Detection Sources

```python
# In src/detection_matcher.py

def _search_custom_rules(self, technique_id):
    """Add your own detection repository"""
    custom_repo_path = "/path/to/your/rules"
    
    matches = []
    for rule_file in Path(custom_repo_path).rglob("*.yml"):
        with open(rule_file) as f:
            content = f.read()
            if technique_id in content:
                matches.append({
                    'title': 'Custom Rule',
                    'repository': 'custom',
                    'file_path': str(rule_file)
                })
    
    return matches
```

---

## Performance Optimization

### LLM Call Optimization:

```python
# Default: 7 LLM calls
# - 1 for parsing
# - 3 for Sigma rules (top 3 gaps)
# - 3 for hunting queries (1 type per gap)
# - 1 for behavioral patterns

# Enable comprehensive mode for more coverage
# .env
ENABLE_MULTI_QUERY_TYPES=true

# This generates 10 LLM calls:
# - 1 for parsing
# - 3 for Sigma rules
# - 6 for hunting queries (2 types per gap)
# - 1 for behavioral patterns
```

### Caching Strategy:

```python
# Repositories are cloned once and reused
# No need to re-download on each run

# To force update:
rm -rf ~/.t2de/repositories
python main.py --input report.txt --output analysis.md
```

---

## Error Handling

### LLM Errors:

```python
try:
    response = self.llm.invoke(prompt)
except Exception as e:
    print(f"Error generating detection: {e}")
    return {
        'technique_id': gap.technique_id,
        'sigma_rule': 'Error generating rule',
        'confidence': 'Error',
        'requires_validation': True
    }
```

### Repository Errors:

```python
try:
    git.Repo.clone_from(repo_url, repo_path)
except git.GitCommandError as e:
    print(f"Error cloning repository: {e}")
    print("Continuing with existing local copy...")
```

---

## Testing

### Unit Tests:

```python
# Test context building
def test_build_attack_context():
    gap = DetectionGap(technique_id="T1055", ...)
    attack_chain = [
        AttackStep(technique_id="T1566", ...),
        AttackStep(technique_id="T1055", description="Process injection"),
        AttackStep(technique_id="T1486", ...)
    ]
    
    suggester = DetectionSuggester()
    context = suggester._build_attack_context(gap, attack_chain)
    
    assert "Process injection" in context
    assert "Previous:" in context
    assert "Next:" in context
```

### Integration Tests:

```python
# Test full pipeline
def test_full_pipeline():
    parser = IntelParser()
    
    threat_report = "Sample threat report..."
    result = parser.parse(threat_report)
    
    assert len(result.attack_chain) > 0
    assert len(result.iocs) > 0
    assert result.coverage_summary is not None
```

---

## Conclusion

T2DE's architecture is designed for:
- **Modularity**: Each component has a single responsibility
- **Extensibility**: Easy to add new LLM providers, detection sources
- **Context-Awareness**: Detections are tailored to specific attacks
- **Type Safety**: Pydantic models ensure data integrity
- **Performance**: Optimized LLM calls, local repository caching

The key innovation is the context-aware detection generation that produces actionable, relevant detections instead of generic technique-based rules.