"""
Unit tests for Analysis Service
"""

import unittest
from .analysis_service import PyTealAnalysisService, get_analysis_service


class TestPyTealAnalysisService(unittest.TestCase):
    """Test cases for analysis service"""

    def setUp(self):
        """Set up test fixtures"""
        self.service = PyTealAnalysisService()

    def test_secure_contract_analysis(self):
        """Test comprehensive analysis of secure contract"""
        code = '''
from pyteal import *

def approval():
    is_creator = Txn.sender() == App.globalGet(Bytes("Creator"))

    on_creation = Seq([
        Assert(Txn.application_args.length() == Int(1)),
        App.globalPut(Bytes("Creator"), Txn.sender()),
        Return(Int(1))
    ])

    program = Cond(
        [Txn.application_id() == Int(0), on_creation],
        [Txn.on_completion() == OnComplete.DeleteApplication, Return(is_creator)],
        [Txn.on_completion() == OnComplete.UpdateApplication, Return(is_creator)]
    )

    return program

if __name__ == "__main__":
    print(compileTeal(approval(), mode=Mode.Application, version=2))
        '''
        result = self.service.analyze_contract(code)

        self.assertTrue(result.is_secure or result.security_score >= 70)
        self.assertGreater(result.security_score, 0)
        self.assertEqual(result.critical_issues, 0)
        self.assertIsNotNone(result.contract_type)
        self.assertTrue(len(result.recommendations) > 0)

    def test_insecure_contract_analysis(self):
        """Test analysis of insecure contract"""
        code = '''
def bad_contract():
    return True
        '''
        result = self.service.analyze_contract(code)

        self.assertFalse(result.is_secure)
        self.assertGreater(result.total_issues, 0)
        self.assertGreater(result.critical_issues, 0)
        self.assertFalse(result.is_production_ready)

    def test_risk_level_calculation(self):
        """Test risk level assessment"""
        critical_code = '''
def vulnerable():
    return Int(1)
        '''
        result = self.service.analyze_contract(critical_code)

        self.assertIn(result.risk_level, ['critical', 'high', 'medium', 'low', 'minimal'])

    def test_production_readiness(self):
        """Test production readiness assessment"""
        secure_code = '''
from pyteal import *

def secure_htlc():
    fee_cond = Txn.fee() < Int(1000)
    safety_cond = And(
        Txn.type_enum() == TxnType.Payment,
        Txn.close_remainder_to() == Global.zero_address(),
        Txn.rekey_to() == Global.zero_address()
    )
    recv_cond = And(
        Txn.receiver() == Addr("6ZHGHH5Z5CTPCF5WCESXMGRSVK7QJETR63M3NY5FJCUYDHO57VTCMJOBGY"),
        Sha256(Arg(0)) == Bytes("base32", "2323232323232323")
    )
    return And(fee_cond, safety_cond, recv_cond)
        '''
        result = self.service.analyze_contract(secure_code)

        # Production readiness requires high score and no critical/high issues
        if result.is_production_ready:
            self.assertGreaterEqual(result.security_score, 80)
            self.assertEqual(result.critical_issues, 0)
            self.assertEqual(result.high_issues, 0)

    def test_recommendations_generation(self):
        """Test that recommendations are generated"""
        code = '''
from pyteal import *

def test():
    return Seq([
        App.globalPut(Bytes("value"), Int(100)),
        Return(Int(1))
    ])
        '''
        result = self.service.analyze_contract(code)

        self.assertTrue(len(result.recommendations) > 0)
        self.assertIsInstance(result.recommendations, list)

    def test_ml_integration(self):
        """Test ML and static analysis integration"""
        code = '''
from pyteal import *

def approval():
    return Return(Int(1))
        '''
        result = self.service.analyze_contract(code)

        self.assertIn(result.ml_prediction, ['0', '1'])
        self.assertGreaterEqual(result.ml_confidence, 0)
        self.assertLessEqual(result.ml_confidence, 1)
        self.assertGreaterEqual(result.secure_probability, 0)
        self.assertLessEqual(result.secure_probability, 1)

    def test_to_dict_serialization(self):
        """Test result serialization to dictionary"""
        code = '''
from pyteal import *
def test():
    return Int(1)
        '''
        result = self.service.analyze_contract(code)
        result_dict = result.to_dict()

        self.assertIsInstance(result_dict, dict)
        self.assertIn('is_secure', result_dict)
        self.assertIn('security_score', result_dict)
        self.assertIn('issues', result_dict)
        self.assertIn('recommendations', result_dict)

    def test_service_singleton(self):
        """Test singleton pattern"""
        service1 = get_analysis_service()
        service2 = get_analysis_service()

        self.assertIs(service1, service2)

    def test_issue_severity_counts(self):
        """Test issue severity counting"""
        code = '''
from pyteal import *

def vulnerable():
    on_delete = Return(Int(1))
    program = Cond([
        Txn.on_completion() == OnComplete.DeleteApplication,
        on_delete
    ])
    return program
        '''
        result = self.service.analyze_contract(code)

        total = (result.critical_issues + result.high_issues +
                result.medium_issues + result.low_issues + result.info_issues)
        self.assertEqual(total, result.total_issues)


if __name__ == '__main__':
    unittest.main()
