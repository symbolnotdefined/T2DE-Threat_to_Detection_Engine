from typing import List, Dict, Any, Set
from .models import AttackStep, MatchedDetection

class CoverageAnalyzer:
    """
    Analyzes detection coverage and identifies gaps in threat detection capabilities.
    """
    
    def __init__(self):
        pass
    
    def analyze_coverage(
        self,
        attack_chain: List[AttackStep],
        matched_detections: List[MatchedDetection],
        atomic_tests: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze detection coverage across the attack chain.
        
        Args:
            attack_chain: List of attack steps with MITRE ATT&CK techniques
            matched_detections: List of matched detection rules
            atomic_tests: Dictionary of atomic tests by technique ID
            
        Returns:
            Comprehensive coverage analysis
        """
        # Extract all techniques from attack chain
        all_techniques = {step.technique_id for step in attack_chain}
        
        # Extract covered techniques from detections
        covered_by_detections = set()
        for detection in matched_detections:
            covered_by_detections.update(detection.matched_techniques)
        
        # Extract techniques with atomic tests
        techniques_with_tests = set(atomic_tests.keys())
        
        # Calculate gaps
        detection_gaps = all_techniques - covered_by_detections
        testing_gaps = all_techniques - techniques_with_tests
        
        # Calculate coverage percentages
        total_techniques = len(all_techniques)
        detection_coverage_pct = (len(covered_by_detections) / total_techniques * 100) if total_techniques > 0 else 0
        testing_coverage_pct = (len(techniques_with_tests) / total_techniques * 100) if total_techniques > 0 else 0
        
        # Build detailed coverage map
        coverage_map = {}
        for step in attack_chain:
            tid = step.technique_id
            
            # Find detections for this technique
            technique_detections = [
                d for d in matched_detections 
                if tid in d.matched_techniques
            ]
            
            # Get atomic tests for this technique
            technique_tests = atomic_tests.get(tid, {})
            
            # Calculate detection score
            detection_score = self._calculate_detection_score(
                technique_detections,
                technique_tests
            )
            
            coverage_map[tid] = {
                'technique_name': step.technique_name,
                'description': step.description,
                'detection_count': len(technique_detections),
                'detections': technique_detections,
                'has_atomic_tests': tid in techniques_with_tests,
                'atomic_test_count': technique_tests.get('test_count', 0),
                'detection_score': detection_score,
                'coverage_grade': self._score_to_grade(detection_score),
                'is_gap': tid in detection_gaps
            }
        
        return {
            'summary': {
                'total_techniques': total_techniques,
                'covered_techniques': len(covered_by_detections),
                'detection_gaps': len(detection_gaps),
                'detection_coverage_percentage': round(detection_coverage_pct, 1),
                'testing_coverage_percentage': round(testing_coverage_pct, 1),
                'total_detections': len(matched_detections),
                'techniques_with_tests': len(techniques_with_tests)
            },
            'covered_techniques': sorted(list(covered_by_detections)),
            'detection_gaps': sorted(list(detection_gaps)),
            'testing_gaps': sorted(list(testing_gaps)),
            'coverage_map': coverage_map
        }
    
    def _calculate_detection_score(
        self,
        detections: List[MatchedDetection],
        atomic_tests: Dict[str, Any]
    ) -> int:
        """
        Calculate a detection quality score (0-100) for a technique.
        
        Scoring factors:
        - Number of detections (max 40 points)
        - Detection diversity/sources (max 20 points)
        - Detection maturity (max 20 points)
        - Atomic test availability (max 20 points)
        """
        score = 0
        
        if not detections and not atomic_tests:
            return 0
        
        # Factor 1: Number of detections (max 40 points)
        # 1 detection = 15 pts, 2 = 25 pts, 3 = 35 pts, 4+ = 40 pts
        detection_count = len(detections)
        if detection_count == 1:
            score += 15
        elif detection_count == 2:
            score += 25
        elif detection_count == 3:
            score += 35
        elif detection_count >= 4:
            score += 40
        
        # Factor 2: Detection diversity (max 20 points)
        # Multiple sources = better coverage
        if detections:
            sources = set(d.repository for d in detections)
            if len(sources) == 1:
                score += 10
            elif len(sources) >= 2:
                score += 20
        
        # Factor 3: Detection maturity (max 20 points)
        # Based on severity/level of detections
        if detections:
            maturity_scores = {'critical': 20, 'high': 15, 'medium': 10, 'low': 5, 'informational': 3}
            levels = [d.level for d in detections if d.level]
            if levels:
                avg_maturity = sum(maturity_scores.get(level.lower(), 5) for level in levels) / len(levels)
                score += int(avg_maturity)
        
        # Factor 4: Atomic test coverage (max 20 points)
        if atomic_tests:
            test_count = atomic_tests.get('test_count', 0)
            if test_count == 1:
                score += 10
            elif test_count >= 2:
                score += 20
        
        return min(score, 100)
    
    def _score_to_grade(self, score: int) -> str:
        """Convert numeric score to letter grade."""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def identify_critical_gaps(
        self,
        coverage_analysis: Dict[str, Any],
        attack_chain: List[AttackStep]
    ) -> List[Dict[str, Any]]:
        """
        Identify and prioritize critical detection gaps.
        
        Args:
            coverage_analysis: Output from analyze_coverage()
            attack_chain: Original attack chain for context
            
        Returns:
            List of prioritized gaps with recommendations
        """
        gaps = []
        coverage_map = coverage_analysis['coverage_map']
        
        for step in attack_chain:
            tid = step.technique_id
            coverage = coverage_map.get(tid, {})
            
            if coverage.get('is_gap', False):
                # Determine priority based on position in kill chain
                # Earlier steps are often more critical
                position = attack_chain.index(step) + 1
                total_steps = len(attack_chain)
                
                # Priority scoring
                if position <= total_steps * 0.3:  # First 30% of attack
                    priority = 'CRITICAL'
                    priority_score = 100
                elif position <= total_steps * 0.6:  # Middle 30%
                    priority = 'HIGH'
                    priority_score = 75
                else:  # Last 40%
                    priority = 'MEDIUM'
                    priority_score = 50
                
                gaps.append({
                    'technique_id': tid,
                    'technique_name': step.technique_name,
                    'description': step.description,
                    'priority': priority,
                    'priority_score': priority_score,
                    'position_in_chain': position,
                    'has_atomic_tests': coverage.get('has_atomic_tests', False),
                    'recommendation': self._generate_gap_recommendation(step, coverage)
                })
        
        # Sort by priority score (descending)
        gaps.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return gaps
    
    def _generate_gap_recommendation(
        self,
        step: AttackStep,
        coverage: Dict[str, Any]
    ) -> str:
        """Generate actionable recommendation for a detection gap."""
        recommendations = []
        
        if coverage.get('has_atomic_tests', False):
            recommendations.append(
                f"Validate detection capability using {coverage.get('atomic_test_count', 0)} "
                f"available Atomic Red Team tests"
            )
        else:
            recommendations.append(
                "No Atomic tests available - consider creating custom test scenarios"
            )
        
        recommendations.append(
            f"Develop detection for {step.technique_name} focusing on: {step.description[:100]}..."
        )
        
        recommendations.append(
            "Review MITRE ATT&CK for data sources and detection opportunities"
        )
        
        return " | ".join(recommendations)
    
    def generate_coverage_summary(
        self,
        coverage_analysis: Dict[str, Any]
    ) -> str:
        """
        Generate a human-readable coverage summary.
        
        Args:
            coverage_analysis: Output from analyze_coverage()
            
        Returns:
            Formatted summary string
        """
        summary = coverage_analysis['summary']
        
        lines = []
        lines.append("=" * 60)
        lines.append("DETECTION COVERAGE ANALYSIS")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Total Techniques Analyzed: {summary['total_techniques']}")
        lines.append(f"Techniques with Detections: {summary['covered_techniques']} "
                    f"({summary['detection_coverage_percentage']}%)")
        lines.append(f"Detection Gaps: {summary['detection_gaps']}")
        lines.append(f"Total Detection Rules Found: {summary['total_detections']}")
        lines.append(f"Techniques with Atomic Tests: {summary['techniques_with_tests']} "
                    f"({summary['testing_coverage_percentage']}%)")
        lines.append("")
        
        # Coverage grade
        coverage_pct = summary['detection_coverage_percentage']
        if coverage_pct >= 90:
            grade = "EXCELLENT"
            emoji = "🟢"
        elif coverage_pct >= 75:
            grade = "GOOD"
            emoji = "🟡"
        elif coverage_pct >= 50:
            grade = "FAIR"
            emoji = "🟠"
        else:
            grade = "POOR"
            emoji = "🔴"
        
        lines.append(f"Overall Coverage Grade: {emoji} {grade}")
        lines.append("=" * 60)
        
        return "\n".join(lines)

