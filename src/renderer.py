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
                    
                    # Show relevance score if available (context-aware matching)
                    if det.relevance_score is not None:
                        score_emoji = "🟢" if det.relevance_score >= 8 else "🟡" if det.relevance_score >= 6 else "🟠"
                        md += f"- **Relevance Score:** {score_emoji} {det.relevance_score}/10\n"
                        if det.relevance_reasoning:
                            md += f"- **Why Relevant:** {det.relevance_reasoning}\n"
                    
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
                    
                    # Show relevance score if available (context-aware matching)
                    if det.relevance_score is not None:
                        score_emoji = "🟢" if det.relevance_score >= 8 else "🟡" if det.relevance_score >= 6 else "🟠"
                        md += f"- **Relevance Score:** {score_emoji} {det.relevance_score}/10\n"
                        if det.relevance_reasoning:
                            md += f"- **Why Relevant:** {det.relevance_reasoning}\n"
                    
                    if det.matched_techniques:
                        md += f"- **Matched Techniques:** {', '.join(det.matched_techniques)}\n"
                    if det.matched_keywords:
                        md += f"- **Matched Keywords:** {', '.join(det.matched_keywords[:5])}\n"
                    md += f"- **Source:** [{det.file_path}]({det.url})\n"
                    md += f"- **Repository:** {det.repository}\n\n"
        
        # Add Detection Coverage Analysis
        if report.coverage_summary:
            md += "## Detection Coverage Analysis\n\n"
            summary = report.coverage_summary
            
            # Coverage badge
            coverage_pct = summary['detection_coverage_percentage']
            if coverage_pct >= 90:
                badge = "🟢 EXCELLENT"
            elif coverage_pct >= 75:
                badge = "🟡 GOOD"
            elif coverage_pct >= 50:
                badge = "🟠 FAIR"
            else:
                badge = "🔴 POOR"
            
            md += f"**Overall Coverage:** {badge} ({coverage_pct}%)\n\n"
            
            md += "### Summary\n\n"
            md += f"- **Total Techniques:** {summary['total_techniques']}\n"
            md += f"- **Covered by Detections:** {summary['covered_techniques']} ({coverage_pct}%)\n"
            md += f"- **Detection Gaps:** {summary['detection_gaps']}\n"
            md += f"- **Total Detection Rules:** {summary['total_detections']}\n"
            md += f"- **Techniques with Atomic Tests:** {summary['techniques_with_tests']} ({summary['testing_coverage_percentage']}%)\n\n"
        
        # Add Atomic Red Team Tests
        if report.atomic_tests:
            md += "## Atomic Red Team Test Coverage\n\n"
            md += "*Available tests for validating detection capabilities*\n\n"
            
            for technique_id, test_data in sorted(report.atomic_tests.items()):
                md += f"### {technique_id} - {test_data['technique_name']}\n"
                md += f"**Test Count:** {test_data['test_count']} available tests\n\n"
                
                for test in test_data['tests'][:3]:  # Show first 3 tests
                    md += f"#### Test #{test['test_number']}: {test['name']}\n"
                    md += f"- **Description:** {test['description'][:150]}...\n"
                    md += f"- **Platforms:** {', '.join(test['supported_platforms'])}\n"
                    md += f"- **Executor:** {test['executor']}\n\n"
                
                if test_data['test_count'] > 3:
                    md += f"*...and {test_data['test_count'] - 3} more tests*\n\n"
                
                md += f"[View all tests on GitHub]({test_data['url']})\n\n"
        
        # Add Critical Detection Gaps
        if report.critical_gaps:
            md += "## Critical Detection Gaps\n\n"
            md += "*Prioritized recommendations for detection engineering*\n\n"
            
            for gap in report.critical_gaps:
                priority_emoji = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(gap.priority, '⚪')
                
                md += f"### {priority_emoji} {gap.priority}: {gap.technique_id} - {gap.technique_name}\n\n"
                md += f"**Description:** {gap.description}\n\n"
                md += f"**Has Atomic Tests:** {'✅ Yes' if gap.has_atomic_tests else '❌ No'}\n\n"
                md += f"**Recommendation:**\n{gap.recommendation}\n\n"
                md += "---\n\n"
        
        # Add AI-Generated Sigma Rules
        if report.suggested_sigma_rules:
            md += "## 🤖 AI-Generated Sigma Rules\n\n"
            md += "*Context-aware detection rules tailored to this specific attack (requires validation)*\n\n"
            
            for rule in report.suggested_sigma_rules:
                md += f"### {rule.technique_id} - {rule.technique_name}\n\n"
                md += f"**Confidence:** {rule.confidence} | "
                md += f"**Requires Validation:** {'⚠️ Yes' if rule.requires_validation else '✅ No'}\n\n"
                
                # Add context-aware rationale
                md += "#### 💡 Why This Detection?\n\n"
                md += f"{rule.rationale}\n\n"
                
                md += "#### 🔍 Observed in Attack\n\n"
                md += f"{rule.observed_in_attack}\n\n"
                
                if rule.specific_indicators:
                    md += "#### 🎯 Specific Indicators from This Attack\n\n"
                    for indicator in rule.specific_indicators:
                        md += f"- {indicator}\n"
                    md += "\n"
                
                md += "#### Sigma Rule\n"
                md += "```yaml\n"
                md += rule.sigma_rule
                md += "\n```\n\n"
                
                md += "#### Implementation Details\n\n"
                md += f"**Data Sources Required:**\n{rule.data_sources}\n\n"
                md += f"**Implementation Notes:**\n{rule.implementation_notes}\n\n"
                md += f"**Tuning Recommendations:**\n{rule.tuning_recommendations}\n\n"
                md += f"**Expected False Positive Rate:** {rule.expected_fp_rate}\n\n"
                md += "---\n\n"
        
        # Add Threat Hunting Queries
        if report.hunting_queries:
            md += "## 🎯 Threat Hunting Queries\n\n"
            md += "*Context-aware hunting queries tailored to this specific attack*\n\n"
            
            for query in report.hunting_queries:
                md += f"### {query.technique_id} - {query.technique_name}\n\n"
                md += f"**Query Type:** {query.query_type}\n\n"
                
                # Add context-aware rationale
                md += "#### 💡 Why Hunt for This?\n\n"
                md += f"{query.rationale}\n\n"
                
                md += "#### 🔍 Focus Area in Attack Chain\n\n"
                md += f"{query.observed_in_attack}\n\n"
                
                md += "#### Query\n"
                md += f"```{query.query_type.lower()}\n"
                md += query.query
                md += "\n```\n\n"
                
                md += "#### Hunting Guidance\n\n"
                md += f"**What to Look For:**\n{query.what_to_look_for}\n\n"
                md += f"**Hunting Frequency:** {query.hunting_frequency}\n\n"
                md += f"**Expected FP Rate:** {query.expected_fp_rate}\n\n"
                md += f"**Baseline Notes:**\n{query.baseline_notes}\n\n"
                md += "---\n\n"
        
        # Add Behavioral Patterns
        if report.behavioral_patterns:
            md += "## 🧩 Behavioral Patterns\n\n"
            md += "*Identified attack patterns for detection opportunities*\n\n"
            
            for pattern in report.behavioral_patterns:
                pattern_emoji = {
                    'process_chain': '⚙️',
                    'file_ops': '📁',
                    'network': '🌐',
                    'temporal': '⏱️',
                    'lolbin': '🔧'
                }.get(pattern.pattern_type.lower(), '🔍')
                
                md += f"### {pattern_emoji} {pattern.pattern_type.upper().replace('_', ' ')} Pattern\n\n"
                md += f"**Sequence:**\n{pattern.sequence}\n\n"
                md += f"**Detection Opportunity:**\n{pattern.detection_opportunity}\n\n"
                md += f"**Required Data Sources:**\n{pattern.data_sources}\n\n"
                md += f"**Example Detection Logic:**\n```\n{pattern.example_logic}\n```\n\n"
                md += "---\n\n"
        
        md += "## Indicators of Compromise\n\n"
        md += "| Type | Value | Context |\n| --- | --- | --- |\n"
        for ioc in report.iocs:
            md += f"| {ioc.type} | {ioc.value} | {ioc.context or 'N/A'} |\n"
            
        return md