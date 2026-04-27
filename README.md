# Threat-to-Detection-Engine-T2DE-
Transforming Threat Intelligence into Behavioral Detection Logic

## Features

### 🎯 Core Capabilities
- Parse threat intelligence reports from **text files** or **URLs**
- Extract structured threat data using AI (supports Ollama, Anthropic Claude, OpenAI GPT)
- Map attack chains to **MITRE ATT&CK** techniques
- Generate comprehensive IOC analysis

### 🔍 Detection Matching
- **Automatically match detections** from Sigma and Elastic repositories
- Link to **Atomic Red Team** tests for validation
- Search across 1000+ community detection rules

### 📊 Coverage Analysis
- **Detection gap identification** - find uncovered techniques
- **Coverage scoring** - quantify detection quality (0-100 scale)
- **Priority recommendations** - actionable detection engineering tasks
- Visual coverage grading (A-F scale)

### 🤖 AI-Powered Detection Engineering
- **Auto-generate Sigma rules** for detection gaps
- **Create hunting queries** in multiple formats (Splunk, KQL, EQL)
- **Extract behavioral patterns** from attack chains
- **Suggest data sources** and implementation guidance
- **Provide tuning recommendations** for each detection

### � Testing & Validation
- Map techniques to Atomic Red Team test cases
- Provide validation methodology for each detection
- Show testable attack simulations

### 💰 Cost-Effective
- **Free local option with Ollama** - no API costs!
- Works offline after initial repository cloning

## Installation

```bash
pip3 install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root and configure your preferred LLM provider:

### Option 1: Ollama (Free, Local)

```bash
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
MODEL_TEMPERATURE=0
MODEL_TIMEOUT=60.0
```

**Setup Ollama:**
1. Install Ollama from https://ollama.ai/
2. Pull a model: `ollama pull llama3.1`
3. Start Ollama: `ollama serve`

### Option 2: Anthropic Claude

```bash
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=your_anthropic_api_key_here
MODEL_TEMPERATURE=0
MODEL_TIMEOUT=60.0
```

Get your API key from: https://console.anthropic.com/

### Option 3: OpenAI GPT

```bash
LLM_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key_here
MODEL_TEMPERATURE=0
MODEL_TIMEOUT=60.0
```

Get your API key from: https://platform.openai.com/

### Performance Tuning (Optional)

```bash
# Enable multiple query types for hunting queries (slower but more comprehensive)
# Default: Only generates Splunk queries (7 LLM calls, ~35-210 seconds)
# With this enabled: Generates Splunk + KQL queries (10 LLM calls, ~50-300 seconds)
ENABLE_MULTI_QUERY_TYPES=true
```

**Performance Notes:**
- AI detection generation makes 7 LLM calls by default (3 Sigma rules + 3 hunting queries + 1 pattern extraction)
- Each LLM call takes 5-30 seconds depending on provider and model
- Total time: ~35-210 seconds for default configuration
- Enable `ENABLE_MULTI_QUERY_TYPES=true` for more comprehensive hunting queries at the cost of longer processing time

## Usage

### From a text file:
```bash
python main.py --input data/raw/threat_report.txt --output data/output/analysis.md
```

### From a URL:
```bash
python main.py --input https://example.com/threat-report --output data/output/analysis.md
```

### Arguments:
- `--input`: Path to input text file or URL to threat report (required)
- `--output`: Path to save the markdown output (default: output.md)

## How It Works

1. **Input**: Accepts either a local text file or a URL containing a threat report
2. **Parsing**: Uses LangChain with your chosen LLM to extract structured intelligence
3. **Analysis**: Identifies attack chains with MITRE ATT&CK techniques and IOCs
4. **Detection Matching**: Automatically searches Sigma and Elastic repositories for relevant detection rules
5. **Output**: Generates a formatted markdown report with matched detections and actionable intelligence

### Detection Matching & Coverage Analysis

The tool automatically:
1. **Clones/updates repositories:**
   - [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) - Community detection rules
   - [elastic/detection-rules](https://github.com/elastic/detection-rules) - Elastic SIEM rules
   - [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Attack test cases

2. **Matches detections:**
   - Searches for rules matching MITRE ATT&CK techniques
   - Matches based on keywords from threat intelligence
   - Provides direct GitHub links to detection rules

3. **Analyzes coverage:**
   - Calculates detection coverage percentage
   - Identifies gaps (techniques without detections)
   - Scores detection quality (0-100 scale)
   - Assigns coverage grades (A-F)

4. **Recommends actions:**
   - Prioritizes gaps (CRITICAL, HIGH, MEDIUM, LOW)
   - Links to Atomic Red Team tests for validation
   - Provides actionable detection engineering tasks

**First Run**: The tool will clone repositories (~800MB total). Subsequent runs update via `git pull`.

## Output Structure

The generated report includes:
- **Executive Summary**: High-level overview of the threat
- **Attack Chain**: Sequential steps with MITRE ATT&CK technique mappings
- **Matched Detection Rules**:
  - Sigma rules from SigmaHQ repository
  - Elastic detection rules from elastic/detection-rules
  - Direct links to rule files in GitHub
  - Matched techniques and keywords for each rule
- **Indicators of Compromise (IOCs)**: IPs, domains, hashes, file paths, etc.

## Example Output

The tool generates comprehensive markdown reports with:

### 1. Detection Coverage Analysis
```markdown
## Detection Coverage Analysis

**Overall Coverage:** 🟡 GOOD (75.0%)

### Summary
- **Total Techniques:** 8
- **Covered by Detections:** 6 (75.0%)
- **Detection Gaps:** 2
- **Total Detection Rules:** 12
- **Techniques with Atomic Tests:** 7 (87.5%)
```

### 2. Matched Detection Rules
```markdown
### Sigma Rules

#### Suspicious PowerShell Execution
- **Description:** Detects suspicious PowerShell command execution
- **Severity:** high
- **Matched Techniques:** T1059.001
- **Source:** [Link to GitHub]
- **Repository:** SigmaHQ/sigma
```

### 3. Atomic Red Team Tests
```markdown
## Atomic Red Team Test Coverage

### T1059.001 - PowerShell
**Test Count:** 15 available tests

#### Test #1: PowerShell Execution
- **Description:** Execute PowerShell script...
- **Platforms:** windows
- **Executor:** powershell

[View all tests on GitHub](...)
```

### 4. Critical Detection Gaps
```markdown
## Critical Detection Gaps

### 🔴 CRITICAL: T1055.012 - Process Hollowing

**Description:** Adversary injects code into suspended process...

**Has Atomic Tests:** ✅ Yes

**Recommendation:**
Validate detection capability using 3 available Atomic Red Team tests |
Develop detection for Process Hollowing focusing on: Adversary injects... |
Review MITRE ATT&CK for data sources and detection opportunities
```
