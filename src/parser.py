import os
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from .models import ThreatReport, MatchedDetection, DetectionGap, SuggestedSigmaRule, HuntingQuery, BehavioralPattern
from .detection_matcher import DetectionMatcher
from .coverage_analyzer import CoverageAnalyzer
from .detection_suggester import DetectionSuggester

load_dotenv()

class IntelParser:
    def __init__(self):
        self.llm = self._initialize_llm()
        self.parser = PydanticOutputParser(pydantic_object=ThreatReport)
        self.detection_matcher = DetectionMatcher()
        self.coverage_analyzer = CoverageAnalyzer()
        self.detection_suggester = DetectionSuggester()
    
    def _initialize_llm(self):
        """Initialize the LLM based on the LLM_PROVIDER environment variable."""
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
            raise ValueError(
                f"Unsupported LLM provider: {provider}. "
                "Choose from: anthropic, openai, ollama"
            )
        
    def parse_report(self, report_text: str) -> ThreatReport:
        # First, extract basic threat intelligence without detections
        prompt = ChatPromptTemplate.from_template(
            "Extract structured intelligence from the following threat report.\n"
            "Focus on: title, summary, attack chain with MITRE ATT&CK techniques, and IOCs.\n"
            "Do NOT generate detection rules - leave the detections field empty.\n\n"
            "{format_instructions}\n"
            "Report Content:\n{report_content}"
        )
        
        chain = prompt | self.llm | self.parser
        
        result = chain.invoke({
            "format_instructions": self.parser.get_format_instructions(),
            "report_content": report_text
        })
        
        # Extract technique IDs and keywords for detection matching
        technique_ids = [step.technique_id for step in result.attack_chain]
        
        # Extract keywords from title, summary, and attack descriptions
        keywords = []
        keywords.extend(result.title.split())
        keywords.extend(result.summary.split())
        for step in result.attack_chain:
            keywords.extend(step.technique_name.split())
            keywords.extend(step.description.split()[:5])  # First 5 words of each description
        
        # Remove common words and duplicates
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'been', 'be', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can', 'this', 'that', 'these', 'those'}
        keywords = list(set([kw.lower().strip('.,;:!?()[]{}') for kw in keywords if len(kw) > 3 and kw.lower() not in stop_words]))
        
        # Match detections from repositories
        print("\n" + "="*60)
        print("MATCHING DETECTIONS FROM REPOSITORIES")
        print("="*60)
        matched = self.detection_matcher.match_detections(technique_ids, keywords[:10])
        
        # Convert matched detections to MatchedDetection objects
        detections = []
        for sigma_rule in matched['sigma']:
            detections.append(MatchedDetection(**sigma_rule))
        for elastic_rule in matched['elastic']:
            detections.append(MatchedDetection(**elastic_rule))
        
        result.detections = detections
        result.atomic_tests = matched['atomic_tests']
        
        print(f"\n✓ Total matched detections: {len(detections)}")
        print("="*60 + "\n")
        
        # Perform coverage analysis
        print("="*60)
        print("ANALYZING DETECTION COVERAGE")
        print("="*60)
        
        coverage_analysis = self.coverage_analyzer.analyze_coverage(
            result.attack_chain,
            result.detections,
            result.atomic_tests
        )
        
        # Print coverage summary
        print(self.coverage_analyzer.generate_coverage_summary(coverage_analysis))
        
        # Identify critical gaps
        critical_gaps = self.coverage_analyzer.identify_critical_gaps(
            coverage_analysis,
            result.attack_chain
        )
        
        # Convert to DetectionGap objects
        result.critical_gaps = [DetectionGap(**gap) for gap in critical_gaps]
        result.coverage_summary = coverage_analysis['summary']
        
        if critical_gaps:
            print(f"\n⚠️  Identified {len(critical_gaps)} critical detection gaps")
            for gap in critical_gaps[:3]:  # Show top 3
                print(f"  - {gap['priority']}: {gap['technique_id']} - {gap['technique_name']}")
        
        print("="*60 + "\n")
        
        # Generate AI-powered detection suggestions for critical gaps
        if result.critical_gaps and len(result.critical_gaps) > 0:
            suggestions = self.detection_suggester.generate_suggestions_for_gaps(
                result.critical_gaps,
                result.attack_chain,
                max_suggestions=3  # Generate for top 3 gaps
            )
            
            # Convert to Pydantic models
            result.suggested_sigma_rules = [
                SuggestedSigmaRule(**rule)
                for rule in suggestions['sigma_rules']
            ]
            result.hunting_queries = [
                HuntingQuery(**query)
                for query in suggestions['hunting_queries']
            ]
            result.behavioral_patterns = [
                BehavioralPattern(**pattern)
                for pattern in suggestions['behavioral_patterns']
            ]
            
            print(f"✓ Generated {len(result.suggested_sigma_rules)} Sigma rules")
            print(f"✓ Generated {len(result.hunting_queries)} hunting queries")
            print(f"✓ Identified {len(result.behavioral_patterns)} behavioral patterns\n")
        
        return result