from .models import ThreatReport

class MarkdownRenderer:
    @staticmethod
    def to_markdown(report: ThreatReport) -> str:
        md = f"# {report.title}\n\n"
        md += f"## Executive Summary\n{report.summary}\n\n"
        
        md += "## Attack Chain\n"
        for i, step in enumerate(report.attack_chain, 1):
            md += f"{i}. **{step.technique_name} ({step.technique_id})**: {step.description}\n"
        
        md += "\n## Matched Detection Rules\n\n"
        
        if not report.detections:
            md += "*No detection rules matched from repositories.*\n\n"
        else:
            # Group detections by repository
            sigma_detections = [d for d in report.detections if 'sigma' in d.repository.lower()]
            elastic_detections = [d for d in report.detections if 'elastic' in d.repository.lower()]
            
            if sigma_detections:
                md += "### Sigma Rules\n\n"
                for det in sigma_detections:
                    md += f"#### {det.title}\n"
                    md += f"- **Description:** {det.description}\n"
                    if det.level:
                        md += f"- **Severity:** {det.level}\n"
                    if det.matched_techniques:
                        md += f"- **Matched Techniques:** {', '.join(det.matched_techniques)}\n"
                    if det.matched_keywords:
                        md += f"- **Matched Keywords:** {', '.join(det.matched_keywords[:5])}\n"
                    if det.tags:
                        md += f"- **Tags:** {', '.join(det.tags[:5])}\n"
                    md += f"- **Source:** [{det.file_path}]({det.url})\n"
                    md += f"- **Repository:** {det.repository}\n\n"
            
            if elastic_detections:
                md += "### Elastic Detection Rules\n\n"
                for det in elastic_detections:
                    md += f"#### {det.title}\n"
                    md += f"- **Description:** {det.description}\n"
                    if det.level:
                        md += f"- **Severity:** {det.level}\n"
                    if det.matched_techniques:
                        md += f"- **Matched Techniques:** {', '.join(det.matched_techniques)}\n"
                    if det.matched_keywords:
                        md += f"- **Matched Keywords:** {', '.join(det.matched_keywords[:5])}\n"
                    md += f"- **Source:** [{det.file_path}]({det.url})\n"
                    md += f"- **Repository:** {det.repository}\n\n"
        
        md += "## Indicators of Compromise\n"
        md += "| Type | Value | Context |\n| --- | --- | --- |\n"
        for ioc in report.iocs:
            md += f"| {ioc.type} | {ioc.value} | {ioc.context or 'N/A'} |\n"
            
        return md