# T2DE Documentation

Welcome to the T2DE (Threat-to-Detection Engine) documentation!

## 📚 Documentation Index

### Getting Started
- [Main README](../README.md) - Installation, configuration, and quick start
- [Architecture Mindmap](ARCHITECTURE_MINDMAP.md) - Visual system architecture
- [Code Explanation](CODE_EXPLANATION.md) - Detailed code walkthrough

### Key Concepts
- [Context-Aware Detection Generation](#context-aware-detection-generation)
- [Detection Coverage Analysis](#detection-coverage-analysis)
- [AI-Powered Suggestions](#ai-powered-suggestions)

---

## 🎯 What is T2DE?

T2DE transforms threat intelligence reports into actionable detection logic using AI. Instead of manually creating detection rules, T2DE:

1. **Parses** threat reports to extract structured intelligence
2. **Matches** existing detection rules from community repositories
3. **Analyzes** detection coverage and identifies gaps
4. **Generates** context-aware detection rules for gaps using AI
5. **Produces** comprehensive markdown reports with actionable intelligence

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     T2DE Architecture                        │
└─────────────────────────────────────────────────────────────┘

Input: Threat Report (Text/URL)
   ↓
┌──────────────────┐
│   IntelParser    │ ← Orchestrates entire pipeline
└────────┬─────────┘
         │
         ├─→ LLM (Ollama/Claude/GPT) → Extract structured data
         │
         ├─→ DetectionMatcher → Search Sigma/Elastic/Atomic repos
         │
         ├─→ CoverageAnalyzer → Calculate scores & identify gaps
         │
         ├─→ DetectionSuggester → Generate AI detections
         │
         └─→ ReportRenderer → Create markdown report
                ↓
Output: Comprehensive Analysis Report
```

For detailed architecture diagrams, see [ARCHITECTURE_MINDMAP.md](ARCHITECTURE_MINDMAP.md).

---

## 🔍 Context-Aware Detection Generation

### The Innovation

Traditional detection tools generate **generic** rules based on technique IDs:

```
Input: T1059.003 (PowerShell)
Output: Generic PowerShell detection
Problem: Doesn't match your specific attack
```

T2DE generates **context-aware** detections tailored to your specific attack:

```
Input: 
- Technique: T1059.003
- Attack Context: "Attacker used PowerShell -EncodedCommand 
  to download from evil.com"
- Indicators: powershell.exe, -enc, evil.com

Output: Detection that specifically looks for:
✓ PowerShell with -EncodedCommand
✓ Connections to suspicious domains
✓ Downloads to %TEMP%

Plus:
✓ Rationale: WHY this detection is needed
✓ Attack Mapping: WHERE this appears in the attack
✓ Specific Indicators: WHAT to look for
```

### How It Works

1. **Context Building**: Analyzes the full attack chain to understand:
   - How the technique was used
   - What happened before/after
   - Specific behaviors observed

2. **Indicator Extraction**: Identifies concrete observables:
   - Process names and commands
   - File operations
   - Network activity
   - IOCs (IPs, hashes, domains)

3. **AI Generation**: Creates detections using:
   - Full attack context
   - Specific indicators
   - Attack chain mapping
   - Explicit instructions to focus on THIS attack

4. **Structured Output**: Provides:
   - Detection rule (Sigma YAML)
   - Rationale (WHY needed)
   - Attack mapping (WHERE observed)
   - Specific indicators (WHAT to detect)
   - Implementation guidance

### Example Output

```markdown
### T1055 - Process Injection

#### 💡 Why This Detection?
This detection targets the specific process injection technique where 
malware.exe injected code into svchost.exe, as observed in step 3 of 
the attack chain. The attacker used this to hide malicious activity 
within a legitimate Windows process.

#### 🔍 Observed in Attack
→ Previous: Execution via PowerShell download cradle
→ **Current: Process Injection** (DETECTION GAP)
→ Next: Defense Evasion via process hollowing

#### 🎯 Specific Indicators from This Attack
- Process: malware.exe injecting into svchost.exe
- Memory: Unusual memory allocation in svchost.exe
- IOC (SHA256): abc123...def456 (malware.exe)

#### Sigma Rule
```yaml
title: Suspicious Process Injection into svchost.exe
description: Detects process injection observed in [Attack Name]
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\svchost.exe'
    SourceImage|endswith: '\malware.exe'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1055
```
```

---

## 📊 Detection Coverage Analysis

### Coverage Scoring

T2DE calculates a 0-100 score for each technique based on:

1. **Detection Count** (0-60 points)
   - More detections = better coverage
   - 4+ detections = maximum points

2. **Test Coverage** (0-20 points)
   - Atomic Red Team tests available
   - Can validate detections

3. **Detection Diversity** (0-20 points)
   - Multiple detection approaches
   - Different data sources

### Coverage Grades

| Score | Grade | Meaning |
|-------|-------|---------|
| 90-100 | A | Excellent coverage |
| 80-89 | B | Good coverage |
| 70-79 | C | Adequate coverage |
| 60-69 | D | Poor coverage |
| 0-59 | F | Critical gap |

### Gap Prioritization

| Priority | Criteria | Action |
|----------|----------|--------|
| CRITICAL | No detections | Immediate action required |
| HIGH | Score < 40 | High priority implementation |
| MEDIUM | Score 40-59 | Improvement recommended |
| LOW | Score 60-69 | Enhancement optional |

---

## 🤖 AI-Powered Suggestions

### What Gets Generated

For each critical gap, T2DE generates:

1. **Sigma Detection Rule**
   - Complete YAML rule
   - Context-aware logic
   - Specific to the attack

2. **Threat Hunting Query**
   - Splunk/KQL/EQL format
   - Proactive hunting
   - Attack-focused

3. **Behavioral Patterns**
   - Process chains
   - File operations
   - Network patterns
   - Temporal sequences

### Generation Process

```
Critical Gap Identified
   ↓
Build Attack Context
   ├─ Find related attack steps
   ├─ Extract specific indicators
   └─ Map attack chain flow
   ↓
Generate Detection
   ├─ Create context-aware prompt
   ├─ Invoke LLM
   └─ Parse structured response
   ↓
Validate & Structure
   ├─ Pydantic model validation
   ├─ Extract all required fields
   └─ Add to report
```

---

## 📖 Usage Guide

### Basic Usage

```bash
# Analyze a threat report
python main.py --input report.txt --output analysis.md

# Analyze from URL
python main.py --input https://example.com/report --output analysis.md
```

### Configuration

Create a `.env` file:

```bash
# LLM Provider (ollama, anthropic, openai)
LLM_PROVIDER=ollama

# Ollama Configuration (free, local)
OLLAMA_MODEL=llama3.1
OLLAMA_BASE_URL=http://localhost:11434

# Performance Tuning
MODEL_TEMPERATURE=0
MODEL_TIMEOUT=60.0

# Optional: Enable multiple query types (slower but comprehensive)
ENABLE_MULTI_QUERY_TYPES=false
```

### Output Structure

The generated markdown report includes:

1. **Executive Summary**
   - Threat overview
   - Key statistics
   - Coverage summary

2. **Attack Chain**
   - Step-by-step breakdown
   - MITRE ATT&CK mapping
   - Technique descriptions

3. **IOCs**
   - Categorized indicators
   - Context for each IOC

4. **Matched Detections**
   - Existing Sigma rules
   - Existing Elastic rules
   - Atomic Red Team tests

5. **Coverage Analysis**
   - Scores and grades
   - Visual badges
   - Gap identification

6. **AI-Generated Detections**
   - Context-aware Sigma rules
   - Threat hunting queries
   - Behavioral patterns

---

## 🔧 Advanced Topics

### Extending T2DE

#### Add New LLM Provider

```python
# In src/parser.py

def _initialize_llm(self):
    provider = os.getenv("LLM_PROVIDER")
    
    if provider == "your_provider":
        return YourLLMClient(
            model="your-model",
            api_key=os.getenv("YOUR_API_KEY")
        )
```

#### Add Custom Detection Repository

```python
# In src/detection_matcher.py

def _search_custom_rules(self, technique_id):
    custom_path = "/path/to/your/rules"
    matches = []
    
    for rule_file in Path(custom_path).rglob("*.yml"):
        # Your search logic
        matches.append(...)
    
    return matches
```

### Performance Optimization

#### LLM Call Reduction

```bash
# Default: 7 LLM calls (~35-210 seconds)
ENABLE_MULTI_QUERY_TYPES=false

# Comprehensive: 10 LLM calls (~50-300 seconds)
ENABLE_MULTI_QUERY_TYPES=true
```

#### Repository Caching

Repositories are cloned once to `~/.t2de/repositories/` and reused:

```bash
# Force repository update
rm -rf ~/.t2de/repositories
python main.py --input report.txt --output analysis.md
```

---

## 🎓 Learning Resources

### Understanding the Code

1. Start with [ARCHITECTURE_MINDMAP.md](ARCHITECTURE_MINDMAP.md)
   - Visual overview of system components
   - Data flow diagrams
   - Component interactions

2. Read [CODE_EXPLANATION.md](CODE_EXPLANATION.md)
   - Detailed code walkthrough
   - Method-by-method explanation
   - Code examples

3. Explore the source code
   - `main.py` - Entry point
   - `src/parser.py` - Main orchestrator
   - `src/detection_suggester.py` - AI generation
   - `src/models.py` - Data structures

### Key Concepts to Understand

1. **Pydantic Models**: Type-safe data structures
2. **LangChain**: LLM orchestration framework
3. **MITRE ATT&CK**: Threat taxonomy
4. **Sigma Rules**: Universal detection format
5. **Context-Aware Generation**: The core innovation

---

## 🐛 Troubleshooting

### Common Issues

#### LLM Connection Errors

```bash
# Check Ollama is running
ollama serve

# Test Ollama connection
curl http://localhost:11434/api/tags

# Check API keys for Claude/GPT
echo $ANTHROPIC_API_KEY
echo $OPENAI_API_KEY
```

#### Repository Clone Errors

```bash
# Check git is installed
git --version

# Check network connectivity
ping github.com

# Manual clone test
git clone https://github.com/SigmaHQ/sigma.git /tmp/test-sigma
```

#### Pydantic Validation Errors

```
Error: Field required [type=missing, input_value=...]
```

**Solution**: The AI response didn't include all required fields. This is usually fixed by:
1. Using a more capable model (e.g., Claude Opus, GPT-4)
2. Increasing MODEL_TIMEOUT for slower models
3. Checking the prompt templates in `src/detection_suggester.py`

---

## 📈 Performance Metrics

### Typical Processing Times

| Component | Time | LLM Calls |
|-----------|------|-----------|
| Threat Parsing | 5-30s | 1 |
| Detection Matching | 1-5s | 0 |
| Coverage Analysis | <1s | 0 |
| AI Suggestions | 30-180s | 7 |
| Report Rendering | <1s | 0 |
| **Total** | **40-220s** | **8** |

### Optimization Tips

1. **Use Local LLM**: Ollama is free and fast
2. **Reduce Query Types**: Default to Splunk only
3. **Cache Repositories**: Don't delete `~/.t2de/`
4. **Limit Suggestions**: Default to top 3 gaps

---

## 🤝 Contributing

### Areas for Contribution

1. **New LLM Providers**: Add support for more models
2. **Detection Sources**: Integrate additional repositories
3. **Output Formats**: JSON, CSV, STIX, etc.
4. **Visualizations**: Attack graphs, coverage charts
5. **Test Coverage**: Unit and integration tests

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/t2de.git
cd t2de

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/

# Run with development settings
python main.py --input test_data/sample.txt --output test_output.md
```

---

## 📝 License

[Your License Here]

---

## 🙏 Acknowledgments

- **SigmaHQ**: Community detection rules
- **Elastic**: Detection rules repository
- **Red Canary**: Atomic Red Team tests
- **MITRE**: ATT&CK framework
- **LangChain**: LLM orchestration

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/t2de/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/t2de/discussions)
- **Email**: your-email@example.com

---

## 🗺️ Roadmap

### Completed ✅
- Threat intelligence parsing
- Detection matching (Sigma, Elastic, Atomic)
- Coverage analysis and scoring
- Context-aware AI detection generation
- Behavioral pattern extraction

### In Progress 🚧
- Knowledge graph generation
- MITRE ATT&CK Navigator export
- Detection engineering recommendations

### Planned 📋
- Multi-language support
- Web interface
- API endpoints
- Detection testing framework
- Integration with SIEM platforms

---

For detailed technical documentation, see:
- [Architecture Mindmap](ARCHITECTURE_MINDMAP.md)
- [Code Explanation](CODE_EXPLANATION.md)
- [Main README](../README.md)