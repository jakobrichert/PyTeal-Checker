"""
Advanced PyTeal Security Analyzer
Performs static code analysis to detect security vulnerabilities and anti-patterns
"""

import re
from typing import List, Dict, Tuple
from dataclasses import dataclass


@dataclass
class SecurityIssue:
    """Represents a security issue found in the code"""
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    category: str
    description: str
    line_number: int = 0
    suggestion: str = ""


class PyTealSecurityAnalyzer:
    """
    Analyzes PyTeal smart contracts for security vulnerabilities and best practices
    """

    def __init__(self):
        self.issues: List[SecurityIssue] = []

    def analyze(self, code: str) -> Tuple[bool, List[SecurityIssue], Dict[str, any]]:
        """
        Performs comprehensive security analysis on PyTeal code

        Args:
            code: The PyTeal smart contract code as a string

        Returns:
            Tuple of (is_secure, issues_list, analysis_report)
        """
        self.issues = []

        # Run all security checks
        self._check_imports(code)
        self._check_rekey_vulnerability(code)
        self._check_close_remainder_vulnerability(code)
        self._check_fee_validation(code)
        self._check_authorization(code)
        self._check_arithmetic_operations(code)
        self._check_time_manipulation(code)
        self._check_random_number_usage(code)
        self._check_delete_update_permissions(code)
        self._check_asset_transfer_validation(code)
        self._check_group_transaction_validation(code)
        self._check_input_validation(code)
        self._check_reentrancy_patterns(code)
        self._check_best_practices(code)

        # Generate analysis report
        report = self._generate_report(code)

        # Determine if code is secure
        critical_issues = [i for i in self.issues if i.severity in ['critical', 'high']]
        is_secure = len(critical_issues) == 0

        return is_secure, self.issues, report

    def _check_imports(self, code: str):
        """Verify proper PyTeal imports"""
        if 'from pyteal import' not in code and 'import pyteal' not in code:
            self.issues.append(SecurityIssue(
                severity='critical',
                category='Imports',
                description='Missing PyTeal import statement',
                suggestion='Add: from pyteal import *'
            ))

    def _check_rekey_vulnerability(self, code: str):
        """Check for rekey vulnerabilities"""
        lines = code.split('\n')

        # Check if rekey_to is validated
        has_rekey_check = bool(re.search(r'Txn\.rekey_to\(\)\s*==\s*Global\.zero_address\(\)', code))
        has_transaction = bool(re.search(r'Txn\.(type_enum|on_completion|application_id)', code))

        if has_transaction and not has_rekey_check:
            for i, line in enumerate(lines, 1):
                if 'Txn.' in line and 'rekey_to' not in line:
                    self.issues.append(SecurityIssue(
                        severity='critical',
                        category='Rekey Vulnerability',
                        description='Missing rekey_to validation - attacker can change account authorization',
                        line_number=i,
                        suggestion='Add: Txn.rekey_to() == Global.zero_address()'
                    ))
                    break

    def _check_close_remainder_vulnerability(self, code: str):
        """Check for close_remainder_to vulnerabilities"""
        lines = code.split('\n')

        has_close_check = bool(re.search(r'Txn\.close_remainder_to\(\)\s*==\s*Global\.zero_address\(\)', code))
        has_payment = bool(re.search(r'TxnType\.Payment|Txn\.type_enum\(\)\s*==\s*TxnType\.Payment', code))

        if has_payment and not has_close_check:
            for i, line in enumerate(lines, 1):
                if 'Payment' in line:
                    self.issues.append(SecurityIssue(
                        severity='critical',
                        category='Close Remainder Vulnerability',
                        description='Missing close_remainder_to validation - attacker can drain account',
                        line_number=i,
                        suggestion='Add: Txn.close_remainder_to() == Global.zero_address()'
                    ))
                    break

    def _check_fee_validation(self, code: str):
        """Check for proper fee validation"""
        has_fee_check = bool(re.search(r'Txn\.fee\(\)\s*[<>=]', code))
        has_transaction = bool(re.search(r'Txn\.(type_enum|on_completion)', code))

        if has_transaction and not has_fee_check:
            self.issues.append(SecurityIssue(
                severity='high',
                category='Fee Validation',
                description='No fee validation - attacker can set arbitrary high fees',
                suggestion='Add fee check: Txn.fee() < Int(max_fee)'
            ))

    def _check_authorization(self, code: str):
        """Check for proper authorization checks"""
        # Check for admin/creator checks
        has_admin_check = bool(re.search(r'(is_admin|is_creator|Txn\.sender\(\)\s*==)', code))
        has_state_changes = bool(re.search(r'(App\.globalPut|App\.localPut|App\.globalDel|App\.localDel)', code))

        if has_state_changes and not has_admin_check:
            self.issues.append(SecurityIssue(
                severity='high',
                category='Authorization',
                description='State changes without authorization checks',
                suggestion='Implement admin/owner authorization checks before state modifications'
            ))

    def _check_arithmetic_operations(self, code: str):
        """Check for potential arithmetic vulnerabilities"""
        # Check for division without zero check
        if re.search(r'/\s*[A-Za-z_]', code):
            self.issues.append(SecurityIssue(
                severity='medium',
                category='Arithmetic Safety',
                description='Division operations detected - ensure divisor is non-zero',
                suggestion='Add validation to ensure divisor is greater than zero'
            ))

        # Check for overflow potential
        if re.search(r'\*\s*[A-Za-z_].*\*', code):
            self.issues.append(SecurityIssue(
                severity='medium',
                category='Arithmetic Safety',
                description='Multiple multiplications detected - potential overflow risk',
                suggestion='Consider using checked arithmetic operations'
            ))

    def _check_time_manipulation(self, code: str):
        """Check for time-based vulnerabilities"""
        if re.search(r'Global\.(round|latest_timestamp)\(\)', code):
            self.issues.append(SecurityIssue(
                severity='low',
                category='Time Manipulation',
                description='Contract uses block time/round - be aware of miner manipulation',
                suggestion='Ensure time-based logic cannot be exploited by round manipulation'
            ))

    def _check_random_number_usage(self, code: str):
        """Check for insecure randomness"""
        if re.search(r'random|rand', code, re.IGNORECASE):
            self.issues.append(SecurityIssue(
                severity='high',
                category='Randomness',
                description='Potential use of insecure randomness',
                suggestion='Use VRF (Verifiable Random Function) for on-chain randomness'
            ))

    def _check_delete_update_permissions(self, code: str):
        """Check delete and update application permissions"""
        has_delete = bool(re.search(r'OnComplete\.DeleteApplication', code))
        has_update = bool(re.search(r'OnComplete\.UpdateApplication', code))

        if has_delete:
            # Check if delete is properly restricted
            delete_pattern = r'OnComplete\.DeleteApplication.*Return\(Int\(1\)\)'
            if re.search(delete_pattern, code):
                self.issues.append(SecurityIssue(
                    severity='critical',
                    category='Application Lifecycle',
                    description='DeleteApplication allows unrestricted deletion',
                    suggestion='Restrict deletion to creator/admin only'
                ))

        if has_update:
            update_pattern = r'OnComplete\.UpdateApplication.*Return\(Int\(1\)\)'
            if re.search(update_pattern, code):
                self.issues.append(SecurityIssue(
                    severity='critical',
                    category='Application Lifecycle',
                    description='UpdateApplication allows unrestricted updates',
                    suggestion='Restrict updates to creator/admin only'
                ))

    def _check_asset_transfer_validation(self, code: str):
        """Check asset transfer validation"""
        if 'AssetTransfer' in code:
            # Check for asset freeze validation
            if 'asset_frozen' not in code.lower():
                self.issues.append(SecurityIssue(
                    severity='medium',
                    category='Asset Security',
                    description='Asset transfers without freeze check',
                    suggestion='Validate asset is not frozen before transfers'
                ))

    def _check_group_transaction_validation(self, code: str):
        """Check group transaction security"""
        if re.search(r'Gtxn\[', code):
            # Check if group size is validated
            if 'Global.group_size()' not in code:
                self.issues.append(SecurityIssue(
                    severity='high',
                    category='Group Transaction Security',
                    description='Group transactions without size validation',
                    suggestion='Validate Global.group_size() to prevent unexpected transactions'
                ))

    def _check_input_validation(self, code: str):
        """Check input validation"""
        if 'Txn.application_args' in code:
            # Check if args length is validated
            if 'application_args.length()' not in code:
                self.issues.append(SecurityIssue(
                    severity='high',
                    category='Input Validation',
                    description='Application arguments used without length validation',
                    suggestion='Validate Txn.application_args.length() before accessing arguments'
                ))

    def _check_reentrancy_patterns(self, code: str):
        """Check for potential reentrancy issues"""
        # In Algorand, reentrancy is less of an issue, but still check patterns
        if re.search(r'App\.globalGet.*App\.globalPut', code):
            self.issues.append(SecurityIssue(
                severity='low',
                category='State Management',
                description='Global state read-modify-write pattern detected',
                suggestion='Ensure state updates follow checks-effects-interactions pattern'
            ))

    def _check_best_practices(self, code: str):
        """Check for general best practices"""
        # Check for Assert usage
        if 'Assert(' in code:
            self.issues.append(SecurityIssue(
                severity='info',
                category='Best Practices',
                description='Using Assert() for validation - good practice',
                suggestion='Continue using Assert for critical validations'
            ))

        # Check for proper mode setting
        if 'compileTeal' in code:
            if 'mode=Mode.Application' not in code and 'mode=Mode.Signature' not in code:
                self.issues.append(SecurityIssue(
                    severity='medium',
                    category='Compilation',
                    description='Missing explicit mode in compileTeal',
                    suggestion='Specify mode=Mode.Application or mode=Mode.Signature'
                ))

        # Check for version specification
        if 'compileTeal' in code and 'version=' not in code:
            self.issues.append(SecurityIssue(
                severity='low',
                category='Version Control',
                description='No TEAL version specified',
                suggestion='Specify version parameter in compileTeal for consistency'
            ))

    def _generate_report(self, code: str) -> Dict[str, any]:
        """Generate comprehensive analysis report"""
        lines = code.split('\n')

        # Count issues by severity
        severity_counts = {
            'critical': len([i for i in self.issues if i.severity == 'critical']),
            'high': len([i for i in self.issues if i.severity == 'high']),
            'medium': len([i for i in self.issues if i.severity == 'medium']),
            'low': len([i for i in self.issues if i.severity == 'low']),
            'info': len([i for i in self.issues if i.severity == 'info'])
        }

        # Calculate security score (0-100)
        security_score = 100
        security_score -= severity_counts['critical'] * 25
        security_score -= severity_counts['high'] * 15
        security_score -= severity_counts['medium'] * 8
        security_score -= severity_counts['low'] * 3
        security_score = max(0, security_score)

        # Detect features
        features = {
            'has_pyteal_import': 'from pyteal import' in code or 'import pyteal' in code,
            'has_authorization': bool(re.search(r'(is_admin|is_creator|Txn\.sender)', code)),
            'has_fee_validation': bool(re.search(r'Txn\.fee\(\)', code)),
            'has_rekey_protection': bool(re.search(r'rekey_to.*zero_address', code)),
            'has_close_protection': bool(re.search(r'close_remainder_to.*zero_address', code)),
            'uses_assertions': 'Assert(' in code,
            'uses_global_state': 'App.global' in code,
            'uses_local_state': 'App.local' in code,
            'has_group_txns': 'Gtxn[' in code,
            'contract_type': self._detect_contract_type(code)
        }

        return {
            'security_score': security_score,
            'total_issues': len(self.issues),
            'severity_counts': severity_counts,
            'features': features,
            'lines_of_code': len(lines),
            'is_production_ready': security_score >= 80 and severity_counts['critical'] == 0
        }

    def _detect_contract_type(self, code: str) -> str:
        """Detect the type of smart contract"""
        if 'mode=Mode.Signature' in code:
            return 'Signature Mode (Logic Sig)'
        elif 'mode=Mode.Application' in code:
            if 'voting' in code.lower() or 'vote' in code.lower():
                return 'Voting Application'
            elif 'token' in code.lower() or 'asset' in code.lower():
                return 'Token/Asset Application'
            elif 'auction' in code.lower():
                return 'Auction Application'
            elif 'escrow' in code.lower() or 'htlc' in code.lower():
                return 'Escrow Application'
            else:
                return 'Stateful Application'
        else:
            return 'Unknown'
