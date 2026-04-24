from .models import ThreatReport

class MarkdownRenderer:
    @staticmethod
    def to_markdown(report: ThreatReport) -> str:
        md = f"# {report.title}\n\n"
        md += f"## Executive Summary\n{report.summary}\n\n"
        
        md += "## Attack Chain\n"
        for i, step in enumerate(report.attack_chain, 1):
            md += f"{i}. **{step.technique_name} ({step.technique_id})**: {step.description}\n"
        
        md += "\n## Potential Detections\n"
        for det in report.detections:
            md += f"### {det.title} [{det.severity}]\n"
            md += f"- **Behavior:** {det.behavior}\n"
            md += f"- **Logic:** `{det.pseudo_query}`\n\n"
            
        md += "## Indicators of Compromise\n"
        md += "| Type | Value | Context |\n| --- | --- | --- |\n"
        for ioc in report.iocs:
            md += f"| {ioc.type} | {ioc.value} | {ioc.context or 'N/A'} |\n"
            
        return md