import os
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from .models import ThreatReport

class IntelParser:
    def __init__(self):
        self.llm = ChatAnthropic(model_name="claude-opus-4", temperature=0, timeout=60.0, stop=None)
        self.parser = PydanticOutputParser(pydantic_object=ThreatReport)
        
    def parse_report(self, report_text: str) -> ThreatReport:
        prompt = ChatPromptTemplate.from_template(
            "Extract structured intelligence from the following threat report.\n"
            "{format_instructions}\n"
            "Report Content:\n{report_content}"
        )
        
        chain = prompt | self.llm | self.parser
        
        result = chain.invoke({
            "format_instructions": self.parser.get_format_instructions(),
            "report_content": report_text
        })
        return result