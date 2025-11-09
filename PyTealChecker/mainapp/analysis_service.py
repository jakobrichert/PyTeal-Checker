"""
Unified Analysis Service
Combines ML predictions with static security analysis for comprehensive contract validation
"""

from typing import Dict, List
from dataclasses import dataclass, asdict
from .security_analyzer import PyTealSecurityAnalyzer, SecurityIssue
from .enhanced_ml_model import get_model


@dataclass
class AnalysisResult:
    """Complete analysis result for a PyTeal contract"""
    # Overall assessment
    is_secure: bool
    security_score: int  # 0-100
    risk_level: str  # 'critical', 'high', 'medium', 'low', 'minimal'

    # ML predictions
    ml_prediction: str  # '1' for secure, '0' for insecure
    ml_confidence: float
    secure_probability: float
    insecure_probability: float

    # Security analysis
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    info_issues: int
    issues: List[Dict]

    # Code metrics
    lines_of_code: int
    contract_type: str
    features: Dict

    # Recommendations
    is_production_ready: bool
    recommendations: List[str]

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class PyTealAnalysisService:
    """
    Unified service for analyzing PyTeal smart contracts
    Combines ML-based classification with static security analysis
    """

    def __init__(self):
        self.security_analyzer = PyTealSecurityAnalyzer()
        self.ml_model = get_model()

    def analyze_contract(self, code: str) -> AnalysisResult:
        """
        Perform comprehensive analysis on a PyTeal contract

        Args:
            code: The PyTeal smart contract code

        Returns:
            AnalysisResult with complete analysis
        """
        # Perform security analysis
        is_secure_static, issues, security_report = self.security_analyzer.analyze(code)

        # Perform ML prediction
        ml_prediction, confidence_scores = self.ml_model.predict(code)

        # Combine results
        # Both ML and static analysis should agree for high confidence
        is_secure = is_secure_static and (ml_prediction == '1')

        # Calculate weighted security score
        # 70% from static analysis, 30% from ML
        static_score = security_report['security_score']
        ml_score = confidence_scores['secure_probability'] * 100
        combined_score = int(0.7 * static_score + 0.3 * ml_score)

        # Determine risk level
        risk_level = self._calculate_risk_level(
            combined_score,
            security_report['severity_counts']
        )

        # Convert issues to dictionaries
        issues_dicts = [
            {
                'severity': issue.severity,
                'category': issue.category,
                'description': issue.description,
                'line_number': issue.line_number,
                'suggestion': issue.suggestion
            }
            for issue in issues
        ]

        # Generate recommendations
        recommendations = self._generate_recommendations(
            security_report,
            issues,
            ml_prediction,
            confidence_scores
        )

        # Determine production readiness
        is_production_ready = (
            combined_score >= 80 and
            security_report['severity_counts']['critical'] == 0 and
            security_report['severity_counts']['high'] == 0 and
            ml_prediction == '1' and
            confidence_scores['overall_confidence'] >= 0.7
        )

        return AnalysisResult(
            is_secure=is_secure,
            security_score=combined_score,
            risk_level=risk_level,
            ml_prediction=ml_prediction,
            ml_confidence=confidence_scores['overall_confidence'],
            secure_probability=confidence_scores['secure_probability'],
            insecure_probability=confidence_scores['insecure_probability'],
            total_issues=len(issues),
            critical_issues=security_report['severity_counts']['critical'],
            high_issues=security_report['severity_counts']['high'],
            medium_issues=security_report['severity_counts']['medium'],
            low_issues=security_report['severity_counts']['low'],
            info_issues=security_report['severity_counts']['info'],
            issues=issues_dicts,
            lines_of_code=security_report['lines_of_code'],
            contract_type=security_report['features']['contract_type'],
            features=security_report['features'],
            is_production_ready=is_production_ready,
            recommendations=recommendations
        )

    def _calculate_risk_level(self, score: int, severity_counts: Dict) -> str:
        """Calculate overall risk level"""
        if severity_counts['critical'] > 0:
            return 'critical'
        elif severity_counts['high'] > 0 or score < 50:
            return 'high'
        elif severity_counts['medium'] > 0 or score < 70:
            return 'medium'
        elif score < 85:
            return 'low'
        else:
            return 'minimal'

    def _generate_recommendations(
        self,
        security_report: Dict,
        issues: List[SecurityIssue],
        ml_prediction: str,
        confidence_scores: Dict
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []

        # Critical issues
        critical_issues = [i for i in issues if i.severity == 'critical']
        if critical_issues:
            recommendations.append(
                f"CRITICAL: Address {len(critical_issues)} critical security issues before deployment"
            )
            for issue in critical_issues[:3]:  # Show top 3
                recommendations.append(f"  - {issue.description}: {issue.suggestion}")

        # High severity issues
        high_issues = [i for i in issues if i.severity == 'high']
        if high_issues:
            recommendations.append(
                f"HIGH PRIORITY: Fix {len(high_issues)} high-severity issues"
            )

        # ML confidence
        if confidence_scores['overall_confidence'] < 0.6:
            recommendations.append(
                "ML model has low confidence - consider adding more security validations"
            )

        # Missing security features
        features = security_report['features']
        if not features['has_rekey_protection']:
            recommendations.append("Add rekey_to validation to prevent account takeover")

        if not features['has_close_protection']:
            recommendations.append("Add close_remainder_to validation to prevent fund drainage")

        if not features['has_fee_validation']:
            recommendations.append("Add fee validation to prevent high transaction costs")

        if not features['has_authorization']:
            recommendations.append("Implement authorization checks for privileged operations")

        # Best practices
        if not features['uses_assertions']:
            recommendations.append("Use Assert() statements for critical validations")

        if security_report['security_score'] >= 80:
            recommendations.append("Good job! Contract follows most security best practices")

        # Production readiness
        if not security_report['is_production_ready']:
            recommendations.append(
                "Contract is NOT production-ready - complete security audit recommended"
            )
        else:
            recommendations.append(
                "Contract appears production-ready, but always get a professional audit"
            )

        return recommendations


# Singleton instance
_service_instance = None


def get_analysis_service() -> PyTealAnalysisService:
    """Get or create the singleton analysis service instance"""
    global _service_instance
    if _service_instance is None:
        _service_instance = PyTealAnalysisService()
    return _service_instance
