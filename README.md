# Threat-to-Detection-Engine-T2DE-
Transforming Threat Intelligence into Behavioral Detection Logic

## Features

- Parse threat intelligence reports from **text files** or **URLs**
- Extract structured threat data using AI (Claude Opus 4)
- Generate detection logic and IOCs
- Output formatted markdown reports

## Installation

```bash
pip3 install -r requirements.txt
```

## Configuration

Create a `.env` file in the project root:

```
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

Get your API key from: https://console.anthropic.com/

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
2. **Parsing**: Uses LangChain and GPT-4 to extract structured intelligence
3. **Analysis**: Identifies attack chains, IOCs, and detection logic
4. **Output**: Generates a formatted markdown report with actionable intelligence

## Output Structure

The generated report includes:
- Executive summary
- Attack chain with MITRE ATT&CK techniques
- Detection logic recommendations
- Indicators of Compromise (IOCs)
