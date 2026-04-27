import os
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from .models import AttackStep, DetectionGap

load_dotenv()

# Performance configuration
# Set ENABLE_MULTI_QUERY_TYPES=true in .env to generate multiple query types (slower but more comprehensive)
ENABLE_MULTI_QUERY_TYPES = os.getenv("ENABLE_MULTI_QUERY_TYPES", "false").lower() == "true"
DEFAULT_QUERY_TYPES = ['splunk', 'kql'] if ENABLE_MULTI_QUERY_TYPES else ['splunk']

class DetectionSuggester:
    """
    AI-powered engine for generating detection rules and hunting queries for gaps.
    
    Performance Note:
    - By default, generates only Splunk queries for speed (7 LLM calls total)
    - Set ENABLE_MULTI_QUERY_TYPES=true to generate Splunk + KQL (10 LLM calls total)
    - Each LLM call takes 5-30 seconds depending on provider/model
    """
    
    def __init__(self):
        self.llm = self._initialize_llm()
    
    def _initialize_llm(self):
        """Initialize the LLM based on environment configuration."""
        provider = os.getenv("LLM_PROVIDER", "ollama").lower()
        temperature = float(os.getenv("MODEL_TEMPERATURE", "0"))
        timeout = float(os.getenv("MODEL_TIMEOUT", "60.0"))
        
        if provider == "anthropic":
            return ChatAnthropic(
                model_name="claude-opus-4",
                temperature=temperature,
                timeout=timeout,
                stop=None
            )
        elif provider == "openai":
            return ChatOpenAI(
                model="gpt-4",
                temperature=temperature,
                timeout=timeout
            )
        elif provider == "ollama":
            model = os.getenv("OLLAMA_MODEL", "llama3.1")
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            return ChatOllama(
                model=model,
                base_url=base_url,
                temperature=temperature
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")
    def _build_attack_context(self, gap: DetectionGap, attack_chain: List[AttackStep]) -> str:
        """Build detailed context about where and how the technique appears in the attack."""
        context_parts = []
        
        # Find steps related to this gap's technique
        related_steps = [
            step for step in attack_chain 
            if gap.technique_id in step.technique_id or gap.technique_name.lower() in step.technique_name.lower()
        ]
        
        if related_steps:
            context_parts.append("**How this technique was used in the attack:**")
            for i, step in enumerate(related_steps, 1):
                context_parts.append(f"{i}. {step.description}")
        
        # Add surrounding context (steps before and after)
        if related_steps and attack_chain:
            first_occurrence = attack_chain.index(related_steps[0])
            context_parts.append("\n**Attack chain context:**")
            
            # Previous step
            if first_occurrence > 0:
                prev_step = attack_chain[first_occurrence - 1]
                context_parts.append(f"→ Previous: {prev_step.technique_name} - {prev_step.description}")
            
            # Current step
            context_parts.append(f"→ **Current: {gap.technique_name}** (DETECTION GAP)")
            
            # Next step
            if first_occurrence < len(attack_chain) - 1:
                next_step = attack_chain[first_occurrence + 1]
                context_parts.append(f"→ Next: {next_step.technique_name} - {next_step.description}")
        
        return "\n".join(context_parts) if context_parts else gap.description
    
    def _extract_specific_indicators(self, gap: DetectionGap, attack_chain: List[AttackStep], iocs: Optional[List[Any]]) -> str:
        """Extract specific indicators related to this technique from the attack."""
        indicators = []
        
        # Find related attack steps
        related_steps = [
            step for step in attack_chain 
            if gap.technique_id in step.technique_id or gap.technique_name.lower() in step.technique_name.lower()
        ]
        
        # Extract patterns from descriptions
        for step in related_steps:
            desc = step.description.lower()
            
            # Look for file names, commands, processes
            if 'powershell' in desc or 'cmd' in desc or '.exe' in desc or '.dll' in desc:
                indicators.append(f"- Process/Command: {step.description}")
            elif 'file' in desc or 'directory' in desc or 'path' in desc:
                indicators.append(f"- File Operation: {step.description}")
            elif 'network' in desc or 'connection' in desc or 'download' in desc:
                indicators.append(f"- Network Activity: {step.description}")
            else:
                indicators.append(f"- Behavior: {step.description}")
        
        # Add relevant IOCs if provided
        if iocs:
            for ioc in iocs[:5]:  # Limit to first 5 IOCs
                if hasattr(ioc, 'value') and hasattr(ioc, 'type'):
                    indicators.append(f"- IOC ({ioc.type}): {ioc.value}")
        
        return "\n".join(indicators) if indicators else "No specific indicators extracted from this attack"
    
    
    def generate_sigma_rule(
        self,
        gap: DetectionGap,
        attack_chain: List[AttackStep],
        iocs: Optional[List[Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate a context-aware Sigma detection rule for a detection gap.
        
        Args:
            gap: Detection gap information
            attack_chain: Full attack chain for context
            iocs: IOCs from the threat report
            
        Returns:
            Dictionary containing the suggested Sigma rule with context
        """
        # Build detailed attack context
        attack_context = self._build_attack_context(gap, attack_chain)
        specific_indicators = self._extract_specific_indicators(gap, attack_chain, iocs)
        
        prompt = ChatPromptTemplate.from_template(
            """You are an expert detection engineer specializing in Sigma rules.

Generate a CONTEXT-AWARE Sigma detection rule based on this SPECIFIC attack:

**Technique:** {technique_id} - {technique_name}
**Gap Description:** {description}

**SPECIFIC ATTACK CONTEXT:**
{attack_context}

**OBSERVED INDICATORS:**
{specific_indicators}

IMPORTANT: Your detection should be tailored to THIS SPECIFIC ATTACK, not a generic detection for the technique.

Create a complete Sigma rule in YAML format that:
1. Detects the SPECIFIC behaviors observed in this attack
2. Uses the actual indicators/patterns from the attack context
3. Includes title, description, logsource, detection, falsepositives, level, tags

Also provide:

RATIONALE:
[Explain WHY this detection is needed based on the SPECIFIC attack behaviors observed]

OBSERVED_IN_ATTACK:
[Describe WHERE in the attack chain this pattern appears and what makes it suspicious]

SPECIFIC_INDICATORS:
[List the specific IOCs, file names, commands, or patterns from THIS attack]

DATA_SOURCES:
[Required data sources]

IMPLEMENTATION_NOTES:
[Implementation guidance]

TUNING_RECOMMENDATIONS:
[How to tune for environment]

EXPECTED_FP_RATE:
[Low/Medium/High with explanation]

Format your response as:

RATIONALE:
[Your rationale here]

OBSERVED_IN_ATTACK:
[Where this appears in the attack]

SPECIFIC_INDICATORS:
- [Indicator 1]
- [Indicator 2]

SIGMA_RULE:
```yaml
[Your Sigma rule here]
```

DATA_SOURCES:
[List required data sources]

IMPLEMENTATION_NOTES:
[Implementation guidance]

TUNING_RECOMMENDATIONS:
[How to tune for environment]

EXPECTED_FP_RATE:
[Low/Medium/High with explanation]
"""
        )
        
        try:
            response = self.llm.invoke(
                prompt.format(
                    technique_id=gap.technique_id,
                    technique_name=gap.technique_name,
                    description=gap.description,
                    attack_context=attack_context,
                    specific_indicators=specific_indicators
                )
            )
            
            # Parse the response
            if hasattr(response, 'content'):
                content = response.content if isinstance(response.content, str) else str(response.content)
            else:
                content = str(response)
            
            # Extract sections with new context-aware fields
            rationale = self._extract_section(content, "RATIONALE:", "OBSERVED_IN_ATTACK:")
            observed = self._extract_section(content, "OBSERVED_IN_ATTACK:", "SPECIFIC_INDICATORS:")
            indicators_text = self._extract_section(content, "SPECIFIC_INDICATORS:", "SIGMA_RULE:")
            sigma_rule = self._extract_section(content, "SIGMA_RULE:", "DATA_SOURCES:")
            data_sources = self._extract_section(content, "DATA_SOURCES:", "IMPLEMENTATION_NOTES:")
            implementation = self._extract_section(content, "IMPLEMENTATION_NOTES:", "TUNING_RECOMMENDATIONS:")
            tuning = self._extract_section(content, "TUNING_RECOMMENDATIONS:", "EXPECTED_FP_RATE:")
            fp_rate = self._extract_section(content, "EXPECTED_FP_RATE:", None)
            
            # Parse specific indicators list
            indicators_list = [
                line.strip().lstrip('-').strip()
                for line in indicators_text.split('\n')
                if line.strip() and line.strip().startswith('-')
            ]
            
            return {
                'technique_id': gap.technique_id,
                'technique_name': gap.technique_name,
                'sigma_rule': sigma_rule.strip(),
                'rationale': rationale.strip(),
                'observed_in_attack': observed.strip(),
                'specific_indicators': indicators_list,
                'data_sources': data_sources.strip(),
                'implementation_notes': implementation.strip(),
                'tuning_recommendations': tuning.strip(),
                'expected_fp_rate': fp_rate.strip(),
                'confidence': 'AI-Generated',
                'requires_validation': True
            }
        except Exception as e:
            print(f"Error generating Sigma rule for {gap.technique_id}: {e}")
            return {
                'technique_id': gap.technique_id,
                'technique_name': gap.technique_name,
                'sigma_rule': 'Error generating rule',
                'rationale': 'Error occurred during generation',
                'observed_in_attack': '',
                'specific_indicators': [],
                'data_sources': '',
                'implementation_notes': '',
                'tuning_recommendations': '',
                'expected_fp_rate': '',
                'confidence': 'Error',
                'requires_validation': True
            }
    
    def generate_hunting_queries(
        self,
        gap: DetectionGap,
        attack_chain: List[AttackStep],
        query_types: List[str] = ['splunk']  # Default to just Splunk for speed
    ) -> List[Dict[str, Any]]:
        """
        Generate context-aware threat hunting queries for a detection gap.
        
        Args:
            gap: Detection gap information
            attack_chain: Full attack chain for context
            query_types: Types of queries to generate (splunk, kql, eql, sql)
            
        Returns:
            List of hunting queries in different formats with attack context
        """
        queries = []
        
        # Build attack context
        attack_context = self._build_attack_context(gap, attack_chain)
        
        for query_type in query_types:
            prompt = ChatPromptTemplate.from_template(
                """You are an expert threat hunter and SIEM analyst.

Generate a CONTEXT-AWARE {query_type} threat hunting query based on this SPECIFIC attack:

**Technique:** {technique_id} - {technique_name}
**Gap Description:** {description}

**SPECIFIC ATTACK CONTEXT:**
{attack_context}

IMPORTANT: Your hunting query should target the SPECIFIC behaviors observed in this attack, not generic technique patterns.

Create a hunting query that:
1. Hunts for the SPECIFIC behaviors from this attack
2. Is practical and can run in production
3. Balances detection coverage with false positive rate
4. Includes comments explaining the logic

Also provide:

RATIONALE:
[Explain WHY hunt for this based on the specific attack behaviors]

OBSERVED_IN_ATTACK:
[Describe WHERE in the attack chain to focus hunting efforts]

WHAT_TO_LOOK_FOR:
[Guidance on analyzing results]

EXPECTED_FP_RATE:
[Low/Medium/High with explanation]

HUNTING_FREQUENCY:
[How often to run this hunt]

BASELINE_NOTES:
[Baselining recommendations]

Format your response as:

RATIONALE:
[Your rationale here]

OBSERVED_IN_ATTACK:
[Where to focus in the attack chain]

QUERY:
```{query_type}
[Your query here with comments]
```

WHAT_TO_LOOK_FOR:
[Guidance on analyzing results]

EXPECTED_FP_RATE:
[Low/Medium/High with explanation]

HUNTING_FREQUENCY:
[How often to run this hunt]

BASELINE_NOTES:
[Baselining recommendations]

QUERY:
```{query_type}
[Your query here with comments]
```

WHAT_TO_LOOK_FOR:
[Guidance on analyzing results]

EXPECTED_FP_RATE:
[Low/Medium/High with explanation]

HUNTING_FREQUENCY:
[How often to run this hunt]

BASELINE_NOTES:
[Baselining recommendations]
"""
            )
            
            try:
                response = self.llm.invoke(
                    prompt.format(
                        query_type=query_type.upper(),
                        technique_id=gap.technique_id,
                        technique_name=gap.technique_name,
                        description=gap.description,
                        attack_context=attack_context
                    )
                )
                
                if hasattr(response, 'content'):
                    content = response.content if isinstance(response.content, str) else str(response.content)
                else:
                    content = str(response)
                
                # Extract sections with new context-aware fields
                rationale = self._extract_section(content, "RATIONALE:", "OBSERVED_IN_ATTACK:")
                observed = self._extract_section(content, "OBSERVED_IN_ATTACK:", "QUERY:")
                query = self._extract_section(content, "QUERY:", "WHAT_TO_LOOK_FOR:")
                what_to_look_for = self._extract_section(content, "WHAT_TO_LOOK_FOR:", "EXPECTED_FP_RATE:")
                fp_rate = self._extract_section(content, "EXPECTED_FP_RATE:", "HUNTING_FREQUENCY:")
                frequency = self._extract_section(content, "HUNTING_FREQUENCY:", "BASELINE_NOTES:")
                baseline = self._extract_section(content, "BASELINE_NOTES:", None)
                
                queries.append({
                    'technique_id': gap.technique_id,
                    'technique_name': gap.technique_name,
                    'query_type': query_type.upper(),
                    'rationale': rationale.strip(),
                    'observed_in_attack': observed.strip(),
                    'query': query.strip(),
                    'what_to_look_for': what_to_look_for.strip(),
                    'expected_fp_rate': fp_rate.strip(),
                    'hunting_frequency': frequency.strip(),
                    'baseline_notes': baseline.strip()
                })
            except Exception as e:
                print(f"Error generating {query_type} query for {gap.technique_id}: {e}")
                continue
        
        return queries
    
    def extract_behavioral_patterns(
        self,
        attack_chain: List[AttackStep]
    ) -> List[Dict[str, Any]]:
        """
        Extract behavioral patterns from the attack chain.
        
        Args:
            attack_chain: List of attack steps
            
        Returns:
            List of identified behavioral patterns
        """
        # Build attack chain context
        chain_description = "\n".join([
            f"{i+1}. {step.technique_name} ({step.technique_id}): {step.description}"
            for i, step in enumerate(attack_chain)
        ])
        
        prompt = ChatPromptTemplate.from_template(
            """You are an expert in threat intelligence and behavioral analysis.

Analyze the following attack chain and identify behavioral patterns that could be used for detection:

{chain_description}

Identify patterns such as:
1. **Process Chains**: Sequences of parent-child process relationships
2. **File Operations**: Create → Modify → Execute → Delete patterns
3. **Network Patterns**: DNS → HTTP → C2 beacon sequences
4. **Temporal Patterns**: Time-based attack sequences
5. **Living-off-the-Land**: Use of legitimate tools in malicious ways

For each pattern, provide:
- Pattern type
- Specific sequence or behavior
- Detection opportunity
- Recommended data sources
- Example detection logic

Format your response as a list of patterns:

PATTERN_1:
Type: [process_chain/file_ops/network/temporal/lolbin]
Sequence: [Describe the pattern]
Detection_Opportunity: [How to detect this]
Data_Sources: [Required logs/telemetry]
Example_Logic: [Pseudo-code or logic]

PATTERN_2:
...
"""
        )
        
        try:
            response = self.llm.invoke(
                prompt.format(chain_description=chain_description)
            )
            
            if hasattr(response, 'content'):
                content = response.content if isinstance(response.content, str) else str(response.content)
            else:
                content = str(response)
            
            # Parse patterns
            patterns = []
            pattern_blocks = content.split('PATTERN_')[1:]  # Skip first empty split
            
            # Map LLM response keys to Pydantic model field names
            key_mapping = {
                'type': 'pattern_type',
                'sequence': 'sequence',
                'detection_opportunity': 'detection_opportunity',
                'data_sources': 'data_sources',
                'example_logic': 'example_logic'
            }
            
            for block in pattern_blocks:
                lines = block.strip().split('\n')
                pattern = {}
                current_key = None
                current_value = []
                
                for line in lines:
                    if ':' in line and any(key in line for key in ['Type:', 'Sequence:', 'Detection_Opportunity:', 'Data_Sources:', 'Example_Logic:']):
                        if current_key:
                            # Map to correct field name
                            mapped_key = key_mapping.get(current_key, current_key)
                            pattern[mapped_key] = '\n'.join(current_value).strip()
                        key, value = line.split(':', 1)
                        current_key = key.strip().lower().replace(' ', '_')
                        current_value = [value.strip()]
                    elif current_key:
                        current_value.append(line.strip())
                
                if current_key:
                    # Map to correct field name
                    mapped_key = key_mapping.get(current_key, current_key)
                    pattern[mapped_key] = '\n'.join(current_value).strip()
                
                # Only add pattern if it has all required fields
                if pattern and all(field in pattern for field in ['pattern_type', 'sequence', 'detection_opportunity', 'data_sources', 'example_logic']):
                    patterns.append(pattern)
            
            return patterns
        except Exception as e:
            print(f"Error extracting behavioral patterns: {e}")
            return []
    
    def _extract_section(self, content: str, start_marker: str, end_marker: Optional[str]) -> str:
        """Extract a section from the LLM response between markers."""
        try:
            start_idx = content.find(start_marker)
            if start_idx == -1:
                return ""
            
            start_idx += len(start_marker)
            
            if end_marker:
                end_idx = content.find(end_marker, start_idx)
                if end_idx == -1:
                    return content[start_idx:].strip()
                return content[start_idx:end_idx].strip()
            else:
                return content[start_idx:].strip()
        except Exception:
            return ""
    
    def generate_suggestions_for_gaps(
        self,
        critical_gaps: List[DetectionGap],
        attack_chain: List[AttackStep],
        max_suggestions: int = 3
    ) -> Dict[str, Any]:
        """
        Generate comprehensive detection suggestions for critical gaps.
        
        Args:
            critical_gaps: List of prioritized detection gaps
            attack_chain: Full attack chain for context
            max_suggestions: Maximum number of gaps to generate suggestions for
            
        Returns:
            Dictionary containing Sigma rules, hunting queries, and patterns
        """
        print(f"\n{'='*60}")
        print("GENERATING AI-POWERED DETECTION SUGGESTIONS")
        print(f"{'='*60}")
        
        # Build attack context
        attack_context = " → ".join([
            f"{step.technique_name}" for step in attack_chain
        ])
        
        suggestions = {
            'sigma_rules': [],
            'hunting_queries': [],
            'behavioral_patterns': []
        }
        
        # Generate Sigma rules for top gaps (pass attack_chain, not string context)
        for gap in critical_gaps[:max_suggestions]:
            print(f"\n🔍 Generating Sigma rule for {gap.technique_id}...")
            sigma_rule = self.generate_sigma_rule(gap, attack_chain)
            if sigma_rule:
                suggestions['sigma_rules'].append(sigma_rule)
                print(f"  ✓ Sigma rule generated")
        
        # Generate hunting queries for top gaps (pass attack_chain, not string context)
        query_types_to_use = DEFAULT_QUERY_TYPES
        for gap in critical_gaps[:max_suggestions]:
            print(f"\n🎯 Generating hunting queries for {gap.technique_id}...")
            queries = self.generate_hunting_queries(gap, attack_chain, query_types_to_use)
            if queries:
                suggestions['hunting_queries'].extend(queries)
                print(f"  ✓ {len(queries)} hunting {'queries' if len(queries) > 1 else 'query'} generated")
        
        # Extract behavioral patterns
        print(f"\n🧩 Extracting behavioral patterns from attack chain...")
        patterns = self.extract_behavioral_patterns(attack_chain)
        if patterns:
            suggestions['behavioral_patterns'] = patterns
            print(f"  ✓ {len(patterns)} behavioral patterns identified")
        
        print(f"\n{'='*60}\n")
        
        return suggestions

# Made with Bob
