"""
Unit tests for PyTeal Security Analyzer
"""

import unittest
from .security_analyzer import PyTealSecurityAnalyzer, SecurityIssue


class TestPyTealSecurityAnalyzer(unittest.TestCase):
    """Test cases for security analyzer"""

    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = PyTealSecurityAnalyzer()

    def test_secure_contract_basic(self):
        """Test analysis of a basic secure contract"""
        code = '''
from pyteal import *

def approval():
    return Seq([
        Assert(And(
            Txn.rekey_to() == Global.zero_address(),
            Txn.close_remainder_to() == Global.zero_address(),
            Txn.fee() < Int(1000)
        )),
        Return(Int(1))
    ])
        '''
        is_secure, issues, report = self.analyzer.analyze(code)

        self.assertTrue(is_secure)
        self.assertEqual(report['severity_counts']['critical'], 0)
        self.assertEqual(report['severity_counts']['high'], 0)
        self.assertTrue(report['features']['has_pyteal_import'])
        self.assertTrue(report['features']['has_rekey_protection'])
        self.assertTrue(report['features']['has_close_protection'])

    def test_missing_pyteal_import(self):
        """Test detection of missing PyTeal import"""
        code = '''
def bad_contract():
    return True
        '''
        is_secure, issues, report = self.analyzer.analyze(code)

        self.assertFalse(is_secure)
        critical_issues = [i for i in issues if i.severity == 'critical']
        self.assertTrue(any('import' in i.description.lower() for i in critical_issues))

    def test_rekey_vulnerability(self):
        """Test detection of rekey vulnerability"""
        code = '''
from pyteal import *

def vulnerable():
    return Seq([
        Assert(Txn.close_remainder_to() == Global.zero_address()),
        Return(Int(1))
    ])
        '''
        is_secure, issues, report = self.analyzer.analyze(code)

        self.assertFalse(is_secure)
        rekey_issues = [i for i in issues if 'rekey' in i.description.lower()]
        self.assertTrue(len(rekey_issues) > 0)
        self.assertEqual(rekey_issues[0].severity, 'critical')

    def test_close_remainder_vulnerability(self):
        """Test detection of close_remainder vulnerability"""
        code = '''
from pyteal import *

def vulnerable():
    return And(
        Txn.type_enum() == TxnType.Payment,
        Txn.rekey_to() == Global.zero_address()
    )
        '''
        is_secure, issues, report = self.analyzer.analyze(code)

        self.assertFalse(is_secure)
        close_issues = [i for i in issues if 'close' in i.description.lower()]
        self.assertTrue(len(close_issues) > 0)

    def test_fee_validation(self):
        """Test detection of missing fee validation"""
        code = '''
from pyteal import *

def no_fee_check():
    return And(
        Txn.type_enum() == TxnType.Payment,
        Txn.rekey_to() == Global.zero_address(),
        Txn.close_remainder_to() == Global.zero_address()
    )
        '''
        is_secure, issues, report = self.analyzer.analyze(code)

        fee_issues = [i for i in issues if 'fee' in i.description.lower()]
        self.assertTrue(len(fee_issues) > 0)

    def test_authorization_checks(self):
        """Test detection of missing authorization"""
        code = '''
from pyteal import *

def no_auth():
    return Seq([
        App.globalPut(Bytes("value"), Int(100)),
        Return(Int(1))
    ])
        '''
        is_secure, issues, report = self.analyzer.analyze(code)

        auth_issues = [i for i in issues if 'authorization' in i.description.lower()]
        self.assertTrue(len(auth_issues) > 0)

    def test_delete_application_security(self):
        """Test detection of unrestricted delete"""
        code = '''
from pyteal import *

def vulnerable_delete():
    program = Cond(
        [Txn.on_completion() == OnComplete.DeleteApplication, Return(Int(1))]
    )
    return program
        '''
        is_secure, issues, report = self.analyzer.analyze(code)

        self.assertFalse(is_secure)
        delete_issues = [i for i in issues if 'delete' in i.description.lower()]
        self.assertTrue(len(delete_issues) > 0)

    def test_group_transaction_validation(self):
        """Test detection of group transaction issues"""
        code = '''
from pyteal import *

def group_txn():
    return Seq([
        Assert(Gtxn[0].amount() > Int(0)),
        Return(Int(1))
    ])
        '''
        is_secure, issues, report = self.analyzer.analyze(code)

        group_issues = [i for i in issues if 'group' in i.description.lower()]
        self.assertTrue(len(group_issues) > 0)

    def test_security_score_calculation(self):
        """Test security score calculation"""
        secure_code = '''
from pyteal import *

def secure():
    return Seq([
        Assert(And(
            Txn.rekey_to() == Global.zero_address(),
            Txn.close_remainder_to() == Global.zero_address(),
            Txn.fee() < Int(1000),
            Txn.sender() == App.globalGet(Bytes("Creator"))
        )),
        Return(Int(1))
    ])
        '''
        is_secure, issues, report = self.analyzer.analyze(secure_code)

        # Secure code should have high score
        self.assertGreaterEqual(report['security_score'], 70)

        insecure_code = '''
def insecure():
    return True
        '''
        is_secure, issues, report = self.analyzer.analyze(insecure_code)

        # Insecure code should have low score
        self.assertLess(report['security_score'], 50)

    def test_contract_type_detection(self):
        """Test contract type detection"""
        app_code = '''
from pyteal import *

if __name__ == "__main__":
    print(compileTeal(approval(), mode=Mode.Application, version=2))
        '''
        is_secure, issues, report = self.analyzer.analyze(app_code)

        self.assertIn('Application', report['features']['contract_type'])

        sig_code = '''
from pyteal import *

if __name__ == "__main__":
    print(compileTeal(htlc(), mode=Mode.Signature, version=2))
        '''
        is_secure, issues, report = self.analyzer.analyze(sig_code)

        self.assertIn('Signature', report['features']['contract_type'])


if __name__ == '__main__':
    unittest.main()
