import os
import subprocess
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml

class DetectionMatcher:
    """
    Matches threat intelligence to existing Sigma and Elastic detection rules
    by cloning and searching local repositories.
    """
    
    def __init__(self, repos_dir: str = "detection_repos"):
        """
        Initialize the detection matcher.
        
        Args:
            repos_dir: Directory to store cloned repositories
        """
        self.repos_dir = Path(repos_dir)
        self.repos_dir.mkdir(exist_ok=True)
        
        self.sigma_repo_url = "https://github.com/SigmaHQ/sigma.git"
        self.sigma_repo_path = self.repos_dir / "sigma"
        
        self.elastic_repo_url = "https://github.com/elastic/detection-rules.git"
        self.elastic_repo_path = self.repos_dir / "detection-rules"
        
        self.art_repo_url = "https://github.com/redcanaryco/atomic-red-team.git"
        self.art_repo_path = self.repos_dir / "atomic-red-team"
        
        # Ensure repos are cloned and up to date
        self._setup_repositories()
    
    def _setup_repositories(self):
        """Clone or update the detection rule repositories."""
        print("Setting up detection rule repositories...")
        
        # Setup Sigma repository
        if self.sigma_repo_path.exists():
            print(f"Updating Sigma repository at {self.sigma_repo_path}...")
            try:
                subprocess.run(
                    ["git", "-C", str(self.sigma_repo_path), "pull"],
                    check=True,
                    capture_output=True,
                    text=True
                )
                print("✓ Sigma repository updated")
            except subprocess.CalledProcessError as e:
                print(f"Warning: Failed to update Sigma repo: {e}")
        else:
            print(f"Cloning Sigma repository to {self.sigma_repo_path}...")
            try:
                subprocess.run(
                    ["git", "clone", self.sigma_repo_url, str(self.sigma_repo_path)],
                    check=True,
                    capture_output=True,
                    text=True
                )
                print("✓ Sigma repository cloned")
            except subprocess.CalledProcessError as e:
                print(f"Error: Failed to clone Sigma repo: {e}")
        
        # Setup Elastic repository
        if self.elastic_repo_path.exists():
            print(f"Updating Elastic detection-rules repository at {self.elastic_repo_path}...")
            try:
                subprocess.run(
                    ["git", "-C", str(self.elastic_repo_path), "pull"],
                    check=True,
                    capture_output=True,
                    text=True
                )
                print("✓ Elastic repository updated")
            except subprocess.CalledProcessError as e:
                print(f"Warning: Failed to update Elastic repo: {e}")
        else:
            print(f"Cloning Elastic detection-rules repository to {self.elastic_repo_path}...")
            try:
                subprocess.run(
                    ["git", "clone", self.elastic_repo_url, str(self.elastic_repo_path)],
                    check=True,
                    capture_output=True,
                    text=True
                )
                print("✓ Elastic repository cloned")
            except subprocess.CalledProcessError as e:
                print(f"Error: Failed to clone Elastic repo: {e}")
        
        # Setup Atomic Red Team repository
        if self.art_repo_path.exists():
            print(f"Updating Atomic Red Team repository at {self.art_repo_path}...")
            try:
                subprocess.run(
                    ["git", "-C", str(self.art_repo_path), "pull"],
                    check=True,
                    capture_output=True,
                    text=True
                )
                print("✓ Atomic Red Team repository updated")
            except subprocess.CalledProcessError as e:
                print(f"Warning: Failed to update Atomic Red Team repo: {e}")
        else:
            print(f"Cloning Atomic Red Team repository to {self.art_repo_path}...")
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", self.art_repo_url, str(self.art_repo_path)],
                    check=True,
                    capture_output=True,
                    text=True
                )
                print("✓ Atomic Red Team repository cloned")
            except subprocess.CalledProcessError as e:
                print(f"Error: Failed to clone Atomic Red Team repo: {e}")
    
    def search_sigma_rules(self, technique_ids: List[str], keywords: List[str]) -> List[Dict[str, Any]]:
        """
        Search Sigma repository for rules matching MITRE ATT&CK techniques and keywords.
        
        Args:
            technique_ids: List of MITRE ATT&CK technique IDs (e.g., ['T1059.003'])
            keywords: List of keywords to search for in rule content
            
        Returns:
            List of matched Sigma rules with metadata
        """
        matched_rules = []
        rules_dir = self.sigma_repo_path / "rules"
        
        if not rules_dir.exists():
            print(f"Warning: Sigma rules directory not found at {rules_dir}")
            return []
        
        # Search for YAML files in the rules directory
        for yaml_file in rules_dir.rglob("*.yml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    rule_data = yaml.safe_load(content)
                    
                    if not rule_data:
                        continue
                    
                    # Check if rule matches technique IDs
                    tags = rule_data.get('tags', [])
                    tags_str = ' '.join(str(tag) for tag in tags).lower()
                    
                    technique_match = any(
                        tid.lower() in tags_str or tid.lower().replace('.', '_') in tags_str
                        for tid in technique_ids
                    )
                    
                    # Check if rule matches keywords
                    content_lower = content.lower()
                    keyword_match = any(
                        keyword.lower() in content_lower
                        for keyword in keywords
                    )
                    
                    if technique_match or keyword_match:
                        matched_rules.append({
                            'title': rule_data.get('title', yaml_file.name),
                            'id': rule_data.get('id', 'N/A'),
                            'description': rule_data.get('description', 'No description'),
                            'level': rule_data.get('level', 'unknown'),
                            'tags': tags,
                            'file_path': str(yaml_file.relative_to(self.sigma_repo_path)),
                            'full_path': str(yaml_file),
                            'repository': 'SigmaHQ/sigma',
                            'url': f"https://github.com/SigmaHQ/sigma/blob/master/{yaml_file.relative_to(self.sigma_repo_path)}",
                            'matched_techniques': [tid for tid in technique_ids if tid.lower() in tags_str],
                            'matched_keywords': [kw for kw in keywords if kw.lower() in content_lower]
                        })
            except Exception as e:
                # Skip files that can't be parsed
                continue
        
        # Sort by relevance (number of matches)
        matched_rules.sort(
            key=lambda x: len(x['matched_techniques']) + len(x['matched_keywords']),
            reverse=True
        )
        
        return matched_rules[:15]  # Return top 15 matches
    
    def search_elastic_rules(self, technique_ids: List[str], keywords: List[str]) -> List[Dict[str, Any]]:
        """
        Search Elastic detection-rules repository for matching rules.
        
        Args:
            technique_ids: List of MITRE ATT&CK technique IDs
            keywords: List of keywords to search for
            
        Returns:
            List of matched Elastic rules with metadata
        """
        matched_rules = []
        rules_dir = self.elastic_repo_path / "rules"
        
        if not rules_dir.exists():
            print(f"Warning: Elastic rules directory not found at {rules_dir}")
            return []
        
        # Search for TOML files in the rules directory
        for toml_file in rules_dir.rglob("*.toml"):
            try:
                with open(toml_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Extract metadata from TOML content
                    name_match = re.search(r'name\s*=\s*"([^"]+)"', content)
                    description_match = re.search(r'description\s*=\s*"""([^"]+)"""', content, re.DOTALL)
                    if not description_match:
                        description_match = re.search(r'description\s*=\s*"([^"]+)"', content)
                    
                    severity_match = re.search(r'severity\s*=\s*"([^"]+)"', content)
                    threat_match = re.findall(r'threat\s*=\s*\[([^\]]+)\]', content, re.DOTALL)
                    
                    # Check for technique IDs in threat section
                    content_lower = content.lower()
                    technique_match = any(
                        tid.lower() in content_lower
                        for tid in technique_ids
                    )
                    
                    # Check for keywords
                    keyword_match = any(
                        keyword.lower() in content_lower
                        for keyword in keywords
                    )
                    
                    if technique_match or keyword_match:
                        matched_rules.append({
                            'title': name_match.group(1) if name_match else toml_file.name,
                            'description': description_match.group(1).strip() if description_match else 'No description',
                            'severity': severity_match.group(1) if severity_match else 'unknown',
                            'file_path': str(toml_file.relative_to(self.elastic_repo_path)),
                            'full_path': str(toml_file),
                            'repository': 'elastic/detection-rules',
                            'url': f"https://github.com/elastic/detection-rules/blob/main/{toml_file.relative_to(self.elastic_repo_path)}",
                            'matched_techniques': [tid for tid in technique_ids if tid.lower() in content_lower],
                            'matched_keywords': [kw for kw in keywords if kw.lower() in content_lower]
                        })
            except Exception as e:
                # Skip files that can't be parsed
                continue
        
        # Sort by relevance
        matched_rules.sort(
            key=lambda x: len(x['matched_techniques']) + len(x['matched_keywords']),
            reverse=True
        )
        
        return matched_rules[:15]  # Return top 15 matches
    
    def search_atomic_tests(self, technique_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Search Atomic Red Team repository for test cases matching MITRE ATT&CK techniques.
        
        Args:
            technique_ids: List of MITRE ATT&CK technique IDs (e.g., ['T1059.003'])
            
        Returns:
            Dictionary mapping technique IDs to their atomic tests
        """
        atomic_tests = {}
        atomics_dir = self.art_repo_path / "atomics"
        
        if not atomics_dir.exists():
            print(f"Warning: Atomic Red Team atomics directory not found at {atomics_dir}")
            return atomic_tests
        
        for technique_id in technique_ids:
            # Atomic Red Team uses technique IDs as directory names
            technique_dir = atomics_dir / technique_id
            
            if not technique_dir.exists():
                continue
            
            # Look for the technique YAML file
            yaml_file = technique_dir / f"{technique_id}.yaml"
            if not yaml_file.exists():
                continue
            
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    test_data = yaml.safe_load(f)
                    
                    if not test_data:
                        continue
                    
                    tests = []
                    atomic_tests_list = test_data.get('atomic_tests', [])
                    
                    for idx, test in enumerate(atomic_tests_list, 1):
                        tests.append({
                            'test_number': idx,
                            'name': test.get('name', 'Unnamed test'),
                            'description': test.get('description', 'No description'),
                            'supported_platforms': test.get('supported_platforms', []),
                            'executor': test.get('executor', {}).get('name', 'unknown'),
                            'auto_generated_guid': test.get('auto_generated_guid', 'N/A')
                        })
                    
                    if tests:
                        atomic_tests[technique_id] = {
                            'technique_name': test_data.get('display_name', technique_id),
                            'test_count': len(tests),
                            'tests': tests,
                            'file_path': str(yaml_file.relative_to(self.art_repo_path)),
                            'url': f"https://github.com/redcanaryco/atomic-red-team/blob/master/{yaml_file.relative_to(self.art_repo_path)}"
                        }
            except Exception as e:
                # Skip files that can't be parsed
                continue
        
        return atomic_tests
    
    def match_detections(self, technique_ids: List[str], keywords: List[str]) -> Dict[str, Any]:
        """
        Match detections from Sigma, Elastic, and Atomic Red Team repositories.
        
        Args:
            technique_ids: List of MITRE ATT&CK technique IDs
            keywords: List of keywords extracted from threat report
            
        Returns:
            Dictionary with 'sigma', 'elastic', and 'atomic_tests' keys
        """
        print(f"\nSearching for detections matching:")
        print(f"  - Techniques: {', '.join(technique_ids)}")
        print(f"  - Keywords: {', '.join(keywords[:5])}{'...' if len(keywords) > 5 else ''}")
        
        sigma_rules = self.search_sigma_rules(technique_ids, keywords)
        print(f"  ✓ Found {len(sigma_rules)} Sigma rules")
        
        elastic_rules = self.search_elastic_rules(technique_ids, keywords)
        print(f"  ✓ Found {len(elastic_rules)} Elastic rules")
        
        atomic_tests = self.search_atomic_tests(technique_ids)
        total_tests = sum(data['test_count'] for data in atomic_tests.values())
        print(f"  ✓ Found {len(atomic_tests)} techniques with {total_tests} Atomic tests")
        
        return {
            'sigma': sigma_rules,
            'elastic': elastic_rules,
            'atomic_tests': atomic_tests
        }

