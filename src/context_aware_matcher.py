import os
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv

load_dotenv()

class ContextAwareMatcher:
    """
    AI-powered context-aware detection matcher that evaluates relevance
    of detections to specific attacks instead of simple keyword matching.
    """
    
    def __init__(self, repos_dir: str = "detection_repos"):
        self.repos_dir = Path(repos_dir)
        self.sigma_repo_path = self.repos_dir / "sigma"
        self.elastic_repo_path = self.repos_dir / "detection-rules"
        self.art_repo_path = self.repos_dir / "atomic-red-team"
        self.llm = self._initialize_llm()
        
        # Relevance threshold (0-10 scale)
        self.relevance_threshold = float(os.getenv("DETECTION_RELEVANCE_THRESHOLD", "7.0"))
    
    def _initialize_llm(self):
        """Initialize LLM for relevance scoring."""
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
    
    def find_relevant_detections(
        self,
        attack_step: Any,
        attack_context: str,
        max_detections: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Find detections that are actually relevant to the specific attack step.
        
        Args:
            attack_step: The attack step to find detections for
            attack_context: Full context of the attack
            max_detections: Maximum number of relevant detections to return
            
        Returns:
            List of relevant detections with relevance scores
        """
        print(f"\n🔍 Finding relevant detections for {attack_step.technique_id}...")
        
        # Step 1: Get candidate detections (broader search)
        candidates = self._get_candidate_detections(attack_step)
        
        if not candidates:
            print(f"  ℹ️  No candidate detections found")
            return []
        
        print(f"  📋 Found {len(candidates)} candidate detections")
        
        # Step 2: AI evaluates relevance of each candidate
        relevant_detections = []
        
        for i, candidate in enumerate(candidates[:20], 1):  # Limit to top 20 candidates
            print(f"  ⚖️  Evaluating candidate {i}/{min(len(candidates), 20)}...", end="\r")
            
            relevance_score, reasoning = self._evaluate_relevance(
                attack_step,
                attack_context,
                candidate
            )
            
            if relevance_score >= self.relevance_threshold:
                candidate['relevance_score'] = relevance_score
                candidate['relevance_reasoning'] = reasoning
                relevant_detections.append(candidate)
        
        print(f"  ✓ Found {len(relevant_detections)} highly relevant detections")
        
        # Sort by relevance score (highest first)
        relevant_detections.sort(key=lambda x: x['relevance_score'], reverse=True)
        
        return relevant_detections[:max_detections]
    
    def _get_candidate_detections(self, attack_step: Any) -> List[Dict[str, Any]]:
        """
        Get candidate detections using technique ID and description keywords.
        This is a broader search that will be filtered by AI relevance scoring.
        """
        candidates = []
        
        # Extract keywords from attack step description
        keywords = self._extract_keywords(attack_step.description)
        
        # Search Sigma rules
        sigma_candidates = self._search_sigma_rules(
            attack_step.technique_id,
            keywords
        )
        candidates.extend(sigma_candidates)
        
        # Search Elastic rules
        elastic_candidates = self._search_elastic_rules(
            attack_step.technique_id,
            keywords
        )
        candidates.extend(elastic_candidates)
        
        return candidates
    
    def _extract_keywords(self, description: str) -> List[str]:
        """Extract meaningful keywords from attack description."""
        # Common security-relevant terms
        keywords = []
        desc_lower = description.lower()
        
        # Process names
        if 'powershell' in desc_lower:
            keywords.append('powershell')
        if 'cmd' in desc_lower or 'command' in desc_lower:
            keywords.append('cmd')
        if 'wmi' in desc_lower:
            keywords.append('wmi')
        if 'registry' in desc_lower:
            keywords.append('registry')
        
        # Actions
        if 'download' in desc_lower:
            keywords.append('download')
        if 'execute' in desc_lower or 'execution' in desc_lower:
            keywords.append('execution')
        if 'inject' in desc_lower:
            keywords.append('injection')
        if 'credential' in desc_lower:
            keywords.append('credential')
        
        # File operations
        if 'file' in desc_lower:
            keywords.append('file')
        if 'delete' in desc_lower:
            keywords.append('delete')
        if 'encrypt' in desc_lower:
            keywords.append('encrypt')
        
        return keywords
    
    def _search_sigma_rules(
        self,
        technique_id: str,
        keywords: List[str]
    ) -> List[Dict[str, Any]]:
        """Search Sigma repository for candidate rules."""
        candidates = []
        
        if not self.sigma_repo_path.exists():
            return candidates
        
        # Search in rules directory
        rules_dir = self.sigma_repo_path / "rules"
        if not rules_dir.exists():
            return candidates
        
        for rule_file in rules_dir.rglob("*.yml"):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Check if technique ID is mentioned
                    if technique_id.lower() in content.lower():
                        rule_data = yaml.safe_load(content)
                        if rule_data:
                            candidates.append({
                                'title': rule_data.get('title', 'Unknown'),
                                'description': rule_data.get('description', ''),
                                'repository': 'SigmaHQ/sigma',
                                'file_path': str(rule_file.relative_to(self.sigma_repo_path)),
                                'url': f"https://github.com/SigmaHQ/sigma/blob/master/{rule_file.relative_to(self.sigma_repo_path)}",
                                'level': rule_data.get('level', 'unknown'),
                                'tags': rule_data.get('tags', []),
                                'detection_logic': rule_data.get('detection', {}),
                                'full_content': content
                            })
            except Exception as e:
                continue
        
        return candidates
    
    def _search_elastic_rules(
        self,
        technique_id: str,
        keywords: List[str]
    ) -> List[Dict[str, Any]]:
        """Search Elastic repository for candidate rules."""
        candidates = []
        
        if not self.elastic_repo_path.exists():
            return candidates
        
        rules_dir = self.elastic_repo_path / "rules"
        if not rules_dir.exists():
            return candidates
        
        for rule_file in rules_dir.rglob("*.toml"):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    if technique_id.lower() in content.lower():
                        # Parse TOML-like content (simplified)
                        title = self._extract_field(content, 'name')
                        description = self._extract_field(content, 'description')
                        
                        candidates.append({
                            'title': title or 'Unknown',
                            'description': description or '',
                            'repository': 'elastic/detection-rules',
                            'file_path': str(rule_file.relative_to(self.elastic_repo_path)),
                            'url': f"https://github.com/elastic/detection-rules/blob/main/{rule_file.relative_to(self.elastic_repo_path)}",
                            'level': 'unknown',
                            'tags': [],
                            'full_content': content
                        })
            except Exception as e:
                continue
        
        return candidates
    
    def _extract_field(self, content: str, field_name: str) -> Optional[str]:
        """Extract field value from TOML-like content."""
        import re
        pattern = rf'{field_name}\s*=\s*["\']([^"\']+)["\']'
        match = re.search(pattern, content)
        return match.group(1) if match else None
    
    def _evaluate_relevance(
        self,
        attack_step: Any,
        attack_context: str,
        detection: Dict[str, Any]
    ) -> tuple[float, str]:
        """
        Use AI to evaluate how relevant a detection is to the specific attack.
        
        Returns:
            (relevance_score, reasoning) where score is 0-10
        """
        prompt = ChatPromptTemplate.from_template(
            """You are a detection engineering expert. Evaluate how relevant this detection rule is to the SPECIFIC attack described.

**ATTACK STEP:**
Technique: {technique_id} - {technique_name}
Description: {attack_description}

**FULL ATTACK CONTEXT:**
{attack_context}

**DETECTION RULE:**
Title: {detection_title}
Description: {detection_description}
Repository: {detection_repo}

**TASK:**
Evaluate if this detection would actually catch the SPECIFIC behaviors described in the attack step.

Consider:
1. Does the detection logic match the specific actions described?
2. Would it trigger on the actual indicators mentioned?
3. Is it too generic or too specific?
4. Would it produce false positives in this context?

**OUTPUT FORMAT:**
SCORE: [0-10, where 10 = perfectly matches this specific attack, 0 = completely irrelevant]
REASONING: [1-2 sentences explaining why this score]

Be strict: Only give high scores (8-10) if the detection would SPECIFICALLY catch this attack's behaviors.
Give medium scores (5-7) if it's somewhat related but not specific.
Give low scores (0-4) if it's generic or not applicable.
"""
        )
        
        try:
            response = self.llm.invoke(
                prompt.format(
                    technique_id=attack_step.technique_id,
                    technique_name=attack_step.technique_name,
                    attack_description=attack_step.description,
                    attack_context=attack_context,
                    detection_title=detection['title'],
                    detection_description=detection['description'],
                    detection_repo=detection['repository']
                )
            )
            
            if hasattr(response, 'content'):
                content = response.content if isinstance(response.content, str) else str(response.content)
            else:
                content = str(response)
            
            # Parse score and reasoning
            score_line = [line for line in content.split('\n') if line.strip().startswith('SCORE:')]
            reasoning_line = [line for line in content.split('\n') if line.strip().startswith('REASONING:')]
            
            if score_line:
                score_text = score_line[0].replace('SCORE:', '').strip()
                # Extract number from text (handle formats like "8/10" or "8")
                import re
                score_match = re.search(r'(\d+(?:\.\d+)?)', score_text)
                score = float(score_match.group(1)) if score_match else 5.0
            else:
                score = 5.0
            
            if reasoning_line:
                reasoning = reasoning_line[0].replace('REASONING:', '').strip()
            else:
                reasoning = "No reasoning provided"
            
            return (score, reasoning)
            
        except Exception as e:
            print(f"\n  ⚠️  Error evaluating relevance: {e}")
            return (5.0, "Error during evaluation")
    
    def find_relevant_atomic_tests(
        self,
        attack_step: Any,
        attack_context: str,
        max_tests: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Find Atomic Red Team tests that are relevant to the specific attack.
        
        Args:
            attack_step: The attack step to find tests for
            attack_context: Full context of the attack
            max_tests: Maximum number of relevant tests to return
            
        Returns:
            List of relevant tests with relevance scores
        """
        print(f"\n🧪 Finding relevant Atomic tests for {attack_step.technique_id}...")
        
        # Get candidate tests
        candidates = self._get_candidate_atomic_tests(attack_step.technique_id)
        
        if not candidates:
            print(f"  ℹ️  No candidate tests found")
            return []
        
        print(f"  📋 Found {len(candidates)} candidate tests")
        
        # AI evaluates relevance
        relevant_tests = []
        
        for i, candidate in enumerate(candidates, 1):
            print(f"  ⚖️  Evaluating test {i}/{len(candidates)}...", end="\r")
            
            relevance_score, reasoning = self._evaluate_test_relevance(
                attack_step,
                attack_context,
                candidate
            )
            
            if relevance_score >= self.relevance_threshold:
                candidate['relevance_score'] = relevance_score
                candidate['relevance_reasoning'] = reasoning
                relevant_tests.append(candidate)
        
        print(f"  ✓ Found {len(relevant_tests)} highly relevant tests")
        
        # Sort by relevance
        relevant_tests.sort(key=lambda x: x['relevance_score'], reverse=True)
        
        return relevant_tests[:max_tests]
    
    def _get_candidate_atomic_tests(self, technique_id: str) -> List[Dict[str, Any]]:
        """Get candidate Atomic Red Team tests for a technique."""
        candidates = []
        
        if not self.art_repo_path.exists():
            return candidates
        
        # Atomic tests are organized by technique ID
        atomics_dir = self.art_repo_path / "atomics"
        technique_dir = atomics_dir / technique_id
        
        if not technique_dir.exists():
            return candidates
        
        # Read the technique YAML file
        technique_file = technique_dir / f"{technique_id}.yaml"
        if not technique_file.exists():
            return candidates
        
        try:
            with open(technique_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                
                if 'atomic_tests' in data:
                    for i, test in enumerate(data['atomic_tests'], 1):
                        candidates.append({
                            'test_number': i,
                            'name': test.get('name', 'Unknown'),
                            'description': test.get('description', ''),
                            'supported_platforms': test.get('supported_platforms', []),
                            'executor': test.get('executor', {}).get('name', 'unknown'),
                            'command': test.get('executor', {}).get('command', ''),
                            'technique_id': technique_id
                        })
        except Exception as e:
            pass
        
        return candidates
    
    def _evaluate_test_relevance(
        self,
        attack_step: Any,
        attack_context: str,
        test: Dict[str, Any]
    ) -> tuple[float, str]:
        """
        Use AI to evaluate how relevant an Atomic test is to the specific attack.
        """
        prompt = ChatPromptTemplate.from_template(
            """You are a detection testing expert. Evaluate how relevant this Atomic Red Team test is to the SPECIFIC attack described.

**ATTACK STEP:**
Technique: {technique_id} - {technique_name}
Description: {attack_description}

**FULL ATTACK CONTEXT:**
{attack_context}

**ATOMIC TEST:**
Name: {test_name}
Description: {test_description}
Command: {test_command}

**TASK:**
Evaluate if this test would accurately simulate the SPECIFIC behaviors described in the attack.

Consider:
1. Does the test replicate the actual attack actions?
2. Would it produce similar artifacts/indicators?
3. Is it too generic or too specific?
4. Would it validate detections for this attack?

**OUTPUT FORMAT:**
SCORE: [0-10, where 10 = perfectly simulates this attack, 0 = completely different]
REASONING: [1-2 sentences explaining why]

Be strict: Only give high scores (8-10) if the test closely mimics this specific attack.
"""
        )
        
        try:
            response = self.llm.invoke(
                prompt.format(
                    technique_id=attack_step.technique_id,
                    technique_name=attack_step.technique_name,
                    attack_description=attack_step.description,
                    attack_context=attack_context,
                    test_name=test['name'],
                    test_description=test['description'],
                    test_command=test.get('command', 'N/A')[:200]  # Limit command length
                )
            )
            
            if hasattr(response, 'content'):
                content = response.content if isinstance(response.content, str) else str(response.content)
            else:
                content = str(response)
            
            # Parse score and reasoning
            import re
            score_match = re.search(r'SCORE:\s*(\d+(?:\.\d+)?)', content)
            reasoning_match = re.search(r'REASONING:\s*(.+?)(?:\n|$)', content, re.DOTALL)
            
            score = float(score_match.group(1)) if score_match else 5.0
            reasoning = reasoning_match.group(1).strip() if reasoning_match else "No reasoning provided"
            
            return (score, reasoning)
            
        except Exception as e:
            print(f"\n  ⚠️  Error evaluating test relevance: {e}")
            return (5.0, "Error during evaluation")
