# Threat-to-Detection-Engine-T2DE-
Transforming Threat Intelligence into Behavioral Detection Logic

## Features

- Parse threat intelligence reports from **text files** or **URLs**
- Extract structured threat data using AI (supports Ollama, Anthropic Claude, OpenAI GPT)
- **Automatically match detections** from Sigma and Elastic repositories
- Generate IOCs and attack chain analysis
- Output formatted markdown reports with detection links
- **Free local option with Ollama** - no API costs!

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

### Detection Matching

The tool automatically:
- Clones/updates [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and [elastic/detection-rules](https://github.com/elastic/detection-rules) repositories locally
- Searches for detection rules matching MITRE ATT&CK techniques from the threat report
- Matches rules based on keywords extracted from the threat intelligence
- Provides direct links to matched detection rules in the repositories
- Groups results by Sigma and Elastic rules for easy reference

**First Run**: The tool will clone the detection repositories (~500MB total). Subsequent runs will update them via `git pull`.

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

```markdown
## Matched Detection Rules

### Sigma Rules

#### Suspicious PowerShell Execution
- **Description:** Detects suspicious PowerShell command execution
- **Severity:** high
- **Matched Techniques:** T1059.001
- **Matched Keywords:** powershell, execution
- **Source:** [rules/windows/process_creation/proc_creation_win_susp_powershell.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/...)
- **Repository:** SigmaHQ/sigma

### Elastic Detection Rules

#### Command Shell Activity
- **Description:** Identifies command shell execution patterns
- **Severity:** medium
- **Matched Techniques:** T1059
- **Source:** [rules/windows/execution_command_shell.toml](https://github.com/elastic/detection-rules/blob/main/rules/...)
- **Repository:** elastic/detection-rules
```
