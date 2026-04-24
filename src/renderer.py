import yaml
from .models import ThreatReport

class MarkdownRenderer:
    @staticmethod
    def to_markdown(report: ThreatReport) -> str:
        md = f"# {report.title}\n\n"
        md += f"## Executive Summary\n{report.summary}\n\n"
        
        md += "## Attack Chain\n"
        for i, step in enumerate(report.attack_chain, 1):
            md += f"{i}. **{step.technique_name} ({step.technique_id})**: {step.description}\n"
        
        md += "\n## Sigma Detection Rules\n\n"
        for det in report.detections:
            md += f"### {det.title}\n\n"
            
            # Build Sigma rule structure
            sigma_rule = {
                "title": det.title,
                "id": None,  # Would be generated with UUID in production
                "status": det.status,
                "description": det.description,
                "references": [],
                "author": "T2DE - Threat to Detection Engine",
                "date": None,  # Would be current date in production
                "tags": det.tags,
                "logsource": det.logsource,
                "detection": det.detection,
                "falsepositives": det.falsepositives,
                "level": det.level
            }
            
            # Remove None values for cleaner output
            sigma_rule = {k: v for k, v in sigma_rule.items() if v is not None and v != []}
            
            # Convert to YAML and add to markdown
            md += "```yaml\n"
            md += yaml.dump(sigma_rule, default_flow_style=False, sort_keys=False, allow_unicode=True)
            md += "```\n\n"
            
        md += "## Indicators of Compromise\n"
        md += "| Type | Value | Context |\n| --- | --- | --- |\n"
        for ioc in report.iocs:
            md += f"| {ioc.type} | {ioc.value} | {ioc.context or 'N/A'} |\n"
            
        return md