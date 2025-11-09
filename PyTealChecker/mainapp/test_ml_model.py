"""
Unit tests for Enhanced ML Model
"""

import unittest
from .enhanced_ml_model import EnhancedPyTealMLModel, get_model


class TestEnhancedPyTealMLModel(unittest.TestCase):
    """Test cases for ML model"""

    def setUp(self):
        """Set up test fixtures"""
        self.model = EnhancedPyTealMLModel()
        self.model.train()

    def test_model_training(self):
        """Test that model trains successfully"""
        self.assertTrue(self.model.trained)

    def test_feature_extraction(self):
        """Test feature extraction"""
        code = '''
from pyteal import *

def test():
    return Seq([
        Assert(Txn.rekey_to() == Global.zero_address()),
        Return(Int(1))
    ])
        '''
        features = self.model.extract_features(code)

        self.assertIn('has_pyteal_import', features)
        self.assertIn('has_rekey_check', features)
        self.assertIn('uses_assert', features)
        self.assertEqual(features['has_pyteal_import'], 1.0)
        self.assertEqual(features['has_rekey_check'], 1.0)
        self.assertEqual(features['uses_assert'], 1.0)

    def test_secure_contract_prediction(self):
        """Test prediction on secure contract"""
        secure_code = '''
from pyteal import *

def approval():
    fee_cond = Txn.fee() < Int(1000)
    safety_cond = And(
        Txn.type_enum() == TxnType.Payment,
        Txn.close_remainder_to() == Global.zero_address(),
        Txn.rekey_to() == Global.zero_address()
    )
    return And(fee_cond, safety_cond)
        '''
        prediction, confidence = self.model.predict(secure_code)

        self.assertEqual(prediction, '1')
        self.assertGreater(confidence['overall_confidence'], 0.5)

    def test_insecure_contract_prediction(self):
        """Test prediction on insecure contract"""
        insecure_code = '''
def bad():
    return True
        '''
        prediction, confidence = self.model.predict(insecure_code)

        self.assertEqual(prediction, '0')
        self.assertGreater(confidence['insecure_probability'], 0.5)

    def test_confidence_scores(self):
        """Test confidence score structure"""
        code = '''
from pyteal import *
def test():
    return Int(1)
        '''
        prediction, confidence = self.model.predict(code)

        self.assertIn('overall_confidence', confidence)
        self.assertIn('text_based_confidence', confidence)
        self.assertIn('feature_based_confidence', confidence)
        self.assertIn('secure_probability', confidence)
        self.assertIn('insecure_probability', confidence)

        # Probabilities should sum to approximately 1
        prob_sum = confidence['secure_probability'] + confidence['insecure_probability']
        self.assertAlmostEqual(prob_sum, 1.0, places=5)

    def test_feature_importance(self):
        """Test feature importance extraction"""
        importances = self.model.get_feature_importance()

        self.assertIsInstance(importances, dict)
        self.assertTrue(len(importances) > 0)

        # All importances should be non-negative
        for importance in importances.values():
            self.assertGreaterEqual(importance, 0)

    def test_model_singleton(self):
        """Test singleton pattern"""
        model1 = get_model()
        model2 = get_model()

        self.assertIs(model1, model2)

    def test_solidity_contract_rejection(self):
        """Test that Solidity contracts are rejected"""
        solidity_code = '''
pragma solidity ^0.8.0;

contract Test {
    function test() public {}
}
        '''
        prediction, confidence = self.model.predict(solidity_code)

        self.assertEqual(prediction, '0')

    def test_code_metrics(self):
        """Test code metric extraction"""
        code = '''
from pyteal import *

def func1():
    return Int(1)

def func2():
    return Int(2)

def main():
    return Seq([
        func1(),
        func2(),
        Return(Int(1))
    ])
        '''
        features = self.model.extract_features(code)

        self.assertGreater(features['function_count'], 0)
        self.assertGreater(features['line_count'], 0)
        self.assertGreater(features['code_length'], 0)


if __name__ == '__main__':
    unittest.main()
