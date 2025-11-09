# PyTeal-Checker 🔐

![Screenshot from 2022-01-31 16-39-08](https://user-images.githubusercontent.com/16466966/151824723-47bcd47d-d808-47b4-81cd-5dfde0b6bc7c.png)

A comprehensive security analysis tool for Algorand PyTeal smart contracts, combining machine learning with static code analysis to detect vulnerabilities and ensure best practices.

**Originally developed for:** [Algorand Developer Tooling Bounty - Schelling Point Hackathon](https://gitcoin.co/issue/algorandfoundation/grow-algorand/132/100027512)

**Live Demo:** https://jakobr21.eu.pythonanywhere.com/

## ✨ Features

### 🔍 Comprehensive Security Analysis
- **Static Code Analysis**: Detects 12+ categories of security vulnerabilities
- **Machine Learning**: Ensemble model with 30+ feature extraction points
- **Security Score**: 0-100 rating system for production readiness
- **Detailed Reports**: Line-by-line issue identification with actionable recommendations

### 🛡️ Security Checks
- Rekey vulnerability detection
- Close remainder vulnerability detection
- Fee validation and manipulation checks
- Authorization and access control verification
- Arithmetic safety (overflow/underflow risks)
- Time manipulation resistance
- Randomness security analysis
- Delete/Update permission validation
- Asset transfer validation
- Group transaction security
- Input validation checks
- Reentrancy pattern detection

### 🤖 Advanced ML Model
- **Ensemble Classification**: Combines Naive Bayes and Random Forest
- **TF-IDF Vectorization**: Advanced text-based pattern recognition
- **Feature Engineering**: 30+ extracted features per contract
- **Confidence Scoring**: Probability-based predictions
- **Self-Training**: Expandable training dataset

### 🌐 REST API
Complete programmatic access via REST endpoints:
- `POST /api/analyze` - Comprehensive contract analysis
- `GET /api/health` - Service health check
- `GET /api/features` - List of analyzed features

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/jakobrichert/PyTeal-Checker.git
cd PyTeal-Checker/PyTealChecker

# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Start the development server
python manage.py runserver
```

### Usage

#### Web Interface
1. Navigate to `http://localhost:8000`
2. Paste your PyTeal smart contract code
3. Click "Check" to receive comprehensive analysis

#### REST API

```bash
# Analyze a contract via API
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "from pyteal import *\n\ndef approval():\n    return Return(Int(1))"}'

# Response includes:
# - Security score (0-100)
# - ML confidence
# - Detailed issues list
# - Risk level assessment
# - Production readiness
# - Actionable recommendations
```

## 📊 Architecture

```
PyTeal-Checker/
├── PyTealChecker/
│   ├── mainapp/
│   │   ├── security_analyzer.py      # Static security analysis
│   │   ├── enhanced_ml_model.py      # ML classification
│   │   ├── analysis_service.py       # Unified analysis service
│   │   ├── views.py                  # Web & API endpoints
│   │   ├── test_*.py                 # Comprehensive tests
│   │   └── templates/                # UI templates
├── examples/
│   ├── secure_voting_app.py         # Secure implementation examples
│   ├── secure_escrow.py             # HTLC with best practices
│   └── insecure_examples.py         # Vulnerability demonstrations
└── README.md
```

### Analysis Pipeline

```
PyTeal Code Input
       ↓
  ┌────────────────┐
  │ Security       │ → 12+ security checks
  │ Analyzer       │ → Pattern detection
  └────────────────┘ → Issue identification
       ↓
  ┌────────────────┐
  │ ML Model       │ → Feature extraction (30+)
  │ (Ensemble)     │ → Text vectorization
  └────────────────┘ → Confidence scoring
       ↓
  ┌────────────────┐
  │ Analysis       │ → Score calculation
  │ Service        │ → Risk assessment
  └────────────────┘ → Recommendation generation
       ↓
  Comprehensive Report
```

## 📖 Example Analysis

### Secure Contract ✅
```python
from pyteal import *

def secure_payment():
    safety_checks = And(
        Txn.type_enum() == TxnType.Payment,
        Txn.rekey_to() == Global.zero_address(),
        Txn.close_remainder_to() == Global.zero_address(),
        Txn.fee() < Int(1000)
    )
    return safety_checks
```

**Result:**
- Security Score: 95/100
- Risk Level: Minimal
- Production Ready: Yes ✓
- Issues: 0 critical, 0 high, 1 medium

### Insecure Contract ❌
```python
def vulnerable():
    return Return(Int(1))  # Missing all security checks!
```

**Result:**
- Security Score: 25/100
- Risk Level: Critical
- Production Ready: No ✗
- Issues: 3 critical, 2 high, 1 medium

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
python manage.py test mainapp

# Run specific test modules
python manage.py test mainapp.test_security_analyzer
python manage.py test mainapp.test_ml_model
python manage.py test mainapp.test_analysis_service
```

Test coverage includes:
- Security analyzer (12+ vulnerability checks)
- ML model (feature extraction, predictions)
- Analysis service (integration, scoring)
- API endpoints
- Edge cases and error handling

## 📚 Documentation

### Security Best Practices

When writing PyTeal contracts, always include:

1. **Rekey Protection**
   ```python
   Assert(Txn.rekey_to() == Global.zero_address())
   ```

2. **Close Remainder Protection**
   ```python
   Assert(Txn.close_remainder_to() == Global.zero_address())
   ```

3. **Fee Validation**
   ```python
   Assert(Txn.fee() <= Int(maximum_fee))
   ```

4. **Authorization Checks**
   ```python
   is_creator = Txn.sender() == App.globalGet(Bytes("Creator"))
   Assert(is_creator)
   ```

5. **Input Validation**
   ```python
   Assert(Txn.application_args.length() == Int(expected_count))
   ```

See the [examples/](examples/) directory for complete secure implementations.

## 🎯 Future Enhancements

- [ ] Expanded training dataset with community contributions
- [ ] Integration with Algorand SDK for live contract testing
- [ ] Visual code highlighting of vulnerabilities
- [ ] IDE plugins (VSCode, PyCharm)
- [ ] Automated fix suggestions with code generation
- [ ] DAO-based security audit marketplace
- [ ] Integration with CI/CD pipelines
- [ ] Support for additional Algorand contract languages

## 📹 Demo Video

https://user-images.githubusercontent.com/16466966/153193970-99345486-2fb0-4910-801e-687a411dc630.mp4

## ⚠️ Disclaimer

**IMPORTANT: This tool is for educational and development assistance purposes only.**

- PyTeal-Checker helps identify common vulnerabilities but is NOT a substitute for professional security audits
- Always have production smart contracts audited by qualified security professionals
- The ML model provides predictions based on patterns - false positives/negatives may occur
- PyTeal-Checker assumes no liability for smart contract security
- Test all contracts thoroughly on TestNet before MainNet deployment

## 🤝 Contributing

Contributions are welcome! Areas for contribution:
- Expanding the training dataset with more contract examples
- Adding new security check patterns
- Improving ML model accuracy
- Documentation and tutorials
- Bug reports and feature requests

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Live Demo**: https://jakobr21.eu.pythonanywhere.com/
- **GitHub**: https://github.com/jakobrichert/PyTeal-Checker
- **Original Bounty**: https://gitcoin.co/issue/algorandfoundation/grow-algorand/132/100027512
- **PyTeal Documentation**: https://pyteal.readthedocs.io/
- **Algorand**: https://www.algorand.com/

## 👤 Author

**Jakob Richert**
- GitHub: [@jakobrichert](https://github.com/jakobrichert)
- Discord: Algorand Community

---

**Built with ❤️ for the Algorand ecosystem**