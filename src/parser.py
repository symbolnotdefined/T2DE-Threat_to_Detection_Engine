import os
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from .models import ThreatReport

load_dotenv()

class IntelParser:
    def __init__(self):
        self.llm = self._initialize_llm()
        self.parser = PydanticOutputParser(pydantic_object=ThreatReport)
    
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
        prompt = ChatPromptTemplate.from_template(
            "Extract structured intelligence from the following threat report.\n"
            "For detections, generate Sigma rules in proper format with:\n"
            "- logsource: dict with category, product, and/or service\n"
            "- detection: dict with selection criteria and condition\n"
            "- level: informational, low, medium, high, or critical\n"
            "- tags: MITRE ATT&CK technique IDs and other relevant tags\n"
            "- falsepositives: list of known false positive scenarios\n\n"
            "Example Sigma detection format:\n"
            "logsource: {{'category': 'process_creation', 'product': 'windows'}}\n"
            "detection: {{'selection': {{'CommandLine|contains': 'powershell'}}, 'condition': 'selection'}}\n\n"
            "{format_instructions}\n"
            "Report Content:\n{report_content}"
        )
        
        chain = prompt | self.llm | self.parser
        
        result = chain.invoke({
            "format_instructions": self.parser.get_format_instructions(),
            "report_content": report_text
        })
        return result