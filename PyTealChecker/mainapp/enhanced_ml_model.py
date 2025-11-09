"""
Enhanced Machine Learning Model for PyTeal Security Analysis
Uses advanced feature extraction and multiple ML techniques
"""

import re
from typing import Dict, List, Tuple
import numpy as np
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.preprocessing import StandardScaler


class EnhancedPyTealMLModel:
    """
    Advanced ML model for PyTeal contract validation using multiple features and ensemble methods
    """

    def __init__(self):
        self.text_vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            token_pattern=r'\b[A-Za-z_][A-Za-z0-9_]*\b'
        )
        self.feature_scaler = StandardScaler()

        # Ensemble of classifiers
        self.nb_classifier = MultinomialNB(alpha=0.1)
        self.rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )

        self.trained = False
        self._init_training_data()

    def _init_training_data(self):
        """Initialize with expanded training dataset"""
        # Secure PyTeal contracts (label: 1)
        secure_contracts = [
            '''from pyteal import *
            def approval():
                return Seq([
                    Assert(And(
                        Txn.rekey_to() == Global.zero_address(),
                        Txn.close_remainder_to() == Global.zero_address(),
                        Txn.fee() < Int(1000)
                    )),
                    Return(Int(1))
                ])''',

            '''from pyteal import *
            def secure_payment():
                safety_checks = And(
                    Txn.type_enum() == TxnType.Payment,
                    Txn.rekey_to() == Global.zero_address(),
                    Txn.close_remainder_to() == Global.zero_address(),
                    Txn.fee() < Int(1000)
                )
                return safety_checks''',

            '''from pyteal import *
            def voting_app():
                is_creator = Txn.sender() == App.globalGet(Bytes("Creator"))
                on_delete = Return(is_creator)
                on_update = Return(is_creator)
                program = Cond(
                    [Txn.on_completion() == OnComplete.DeleteApplication, on_delete],
                    [Txn.on_completion() == OnComplete.UpdateApplication, on_update]
                )
                return program''',

            '''from pyteal import *
            def htlc():
                fee_cond = Txn.fee() < Int(1000)
                safety_cond = And(
                    Txn.type_enum() == TxnType.Payment,
                    Txn.close_remainder_to() == Global.zero_address(),
                    Txn.rekey_to() == Global.zero_address()
                )
                return And(fee_cond, safety_cond)''',

            '''from pyteal import *
            def asset_transfer():
                on_creation = Seq([
                    Assert(Txn.application_args.length() == Int(1)),
                    App.globalPut(Bytes("total"), Btoi(Txn.application_args[0])),
                    Return(Int(1))
                ])
                is_admin = App.localGet(Int(0), Bytes("admin"))
                return Cond(
                    [Txn.application_id() == Int(0), on_creation],
                    [Txn.on_completion() == OnComplete.DeleteApplication, Return(is_admin)]
                )''',
        ]

        # Insecure or malformed contracts (label: 0)
        insecure_contracts = [
            '''from pyteal import *
            def insecure():
                return Return(Int(1))''',  # No security checks

            '''def bad_contract():
                return True''',  # Not even PyTeal

            '''from pyteal import *
            def no_rekey_check():
                return Seq([
                    Assert(Txn.close_remainder_to() == Global.zero_address()),
                    Return(Int(1))
                ])''',  # Missing rekey check

            '''from pyteal import *
            def no_close_check():
                return Seq([
                    Assert(Txn.rekey_to() == Global.zero_address()),
                    Return(Int(1))
                ])''',  # Missing close_remainder check

            '''from pyteal import *
            def unrestricted_delete():
                on_delete = Return(Int(1))
                return Cond([
                    Txn.on_completion() == OnComplete.DeleteApplication,
                    on_delete
                ])''',  # Allows anyone to delete

            '''pragma solidity ^0.8.0;
            contract Wrong {
                function test() public {}
            }''',  # Solidity, not PyTeal

            '''from pyteal import *
            def no_fee_check():
                return And(
                    Txn.type_enum() == TxnType.Payment,
                    Txn.rekey_to() == Global.zero_address()
                )''',  # Missing fee validation

            '''set_admin = Seq([
                App.localPut(Int(1), Bytes("admin"), Int(1)),
                Return(Int(1))
            ])''',  # Incomplete code, missing authorization
        ]

        self.training_data = secure_contracts + insecure_contracts
        self.training_labels = ['1'] * len(secure_contracts) + ['0'] * len(insecure_contracts)

    def extract_features(self, code: str) -> Dict[str, float]:
        """
        Extract numerical features from PyTeal code

        Returns:
            Dictionary of feature names to values
        """
        features = {}

        # Basic metrics
        features['code_length'] = len(code)
        features['line_count'] = len(code.split('\n'))
        features['avg_line_length'] = features['code_length'] / max(features['line_count'], 1)

        # Import checks
        features['has_pyteal_import'] = float('from pyteal import' in code or 'import pyteal' in code)

        # Security feature detection
        features['has_rekey_check'] = float(bool(re.search(r'rekey_to.*zero_address', code)))
        features['has_close_check'] = float(bool(re.search(r'close_remainder_to.*zero_address', code)))
        features['has_fee_check'] = float(bool(re.search(r'Txn\.fee\(\)\s*[<>]', code)))
        features['has_authorization'] = float(bool(re.search(r'(is_admin|is_creator|Txn\.sender\(\)\s*==)', code)))
        features['uses_assert'] = float('Assert(' in code)
        features['has_type_check'] = float(bool(re.search(r'Txn\.type_enum\(\)\s*==', code)))

        # State management
        features['uses_global_state'] = float('App.global' in code)
        features['uses_local_state'] = float('App.local' in code)
        features['has_seq'] = float('Seq(' in code or 'Seq([' in code)
        features['has_cond'] = float('Cond(' in code or 'Cond([' in code)

        # Transaction features
        features['uses_group_txn'] = float('Gtxn[' in code)
        features['has_application_args'] = float('application_args' in code)
        features['has_args_validation'] = float(bool(re.search(r'application_args\.length\(\)', code)))

        # Lifecycle management
        features['handles_delete'] = float('DeleteApplication' in code)
        features['handles_update'] = float('UpdateApplication' in code)
        features['handles_optin'] = float('OptIn' in code)
        features['handles_closeout'] = float('CloseOut' in code)

        # Function definitions
        features['function_count'] = len(re.findall(r'def\s+\w+\s*\(', code))
        features['return_count'] = len(re.findall(r'Return\(', code))

        # Potential issues
        features['has_division'] = float(bool(re.search(r'/\s*[A-Za-z_]', code)))
        features['has_multiplication'] = float(bool(re.search(r'\*\s*[A-Za-z_]', code)))
        features['uses_timestamp'] = float(bool(re.search(r'Global\.(latest_timestamp|round)\(\)', code)))

        # Code quality indicators
        features['has_comments'] = float('#' in code)
        features['has_docstring'] = float('"""' in code or "'''" in code)

        # Keyword density
        pyteal_keywords = ['Txn', 'App', 'Global', 'Int', 'Bytes', 'And', 'Or', 'If', 'Cond', 'Seq']
        for keyword in pyteal_keywords:
            features[f'uses_{keyword.lower()}'] = float(keyword in code)

        return features

    def train(self):
        """Train the ML model on the dataset"""
        # Extract text features
        X_text = self.text_vectorizer.fit_transform(self.training_data)

        # Extract numerical features
        numerical_features = []
        for code in self.training_data:
            feat_dict = self.extract_features(code)
            numerical_features.append(list(feat_dict.values()))

        X_numerical = np.array(numerical_features)

        # Train Naive Bayes on text features
        self.nb_classifier.fit(X_text, self.training_labels)

        # Train Random Forest on numerical features
        self.rf_classifier.fit(X_numerical, self.training_labels)

        self.trained = True

    def predict(self, code: str) -> Tuple[str, Dict[str, float]]:
        """
        Predict if code is secure

        Args:
            code: PyTeal smart contract code

        Returns:
            Tuple of (prediction '1' for secure or '0' for insecure, confidence_scores)
        """
        if not self.trained:
            self.train()

        # Get text-based prediction
        X_text = self.text_vectorizer.transform([code])
        text_pred_proba = self.nb_classifier.predict_proba(X_text)[0]

        # Get feature-based prediction
        feat_dict = self.extract_features(code)
        X_numerical = np.array([list(feat_dict.values())])
        numerical_pred_proba = self.rf_classifier.predict_proba(X_numerical)[0]

        # Weighted ensemble (60% numerical features, 40% text features)
        # Numerical features are more reliable for security analysis
        ensemble_proba = 0.6 * numerical_pred_proba + 0.4 * text_pred_proba

        # Get prediction
        prediction_idx = np.argmax(ensemble_proba)
        prediction = self.nb_classifier.classes_[prediction_idx]

        confidence_scores = {
            'overall_confidence': float(ensemble_proba[prediction_idx]),
            'text_based_confidence': float(text_pred_proba[prediction_idx]),
            'feature_based_confidence': float(numerical_pred_proba[prediction_idx]),
            'secure_probability': float(ensemble_proba[1] if len(ensemble_proba) > 1 else ensemble_proba[0]),
            'insecure_probability': float(ensemble_proba[0] if len(ensemble_proba) > 1 else 1 - ensemble_proba[0])
        }

        return prediction, confidence_scores

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from Random Forest model"""
        if not self.trained:
            self.train()

        # Get feature names
        sample_features = self.extract_features(self.training_data[0])
        feature_names = list(sample_features.keys())

        # Get importances
        importances = self.rf_classifier.feature_importances_

        return dict(zip(feature_names, importances))


# Singleton instance
_model_instance = None


def get_model() -> EnhancedPyTealMLModel:
    """Get or create the singleton model instance"""
    global _model_instance
    if _model_instance is None:
        _model_instance = EnhancedPyTealMLModel()
        _model_instance.train()
    return _model_instance
