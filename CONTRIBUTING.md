# Contributing to PyTeal-Checker

Thank you for your interest in contributing to PyTeal-Checker! This document provides guidelines and instructions for contributing.

## 🎯 Ways to Contribute

### 1. Expand Training Data
Help improve the ML model by adding more PyTeal contract examples:
- Add secure contract examples to `enhanced_ml_model.py`
- Add insecure/vulnerable examples with clear documentation
- Ensure examples represent real-world patterns

### 2. Add Security Checks
Enhance the static analyzer with new vulnerability patterns:
- Edit `security_analyzer.py`
- Add new check methods following existing patterns
- Include severity classification
- Provide clear suggestions for fixes

### 3. Improve Documentation
- Fix typos or unclear explanations
- Add usage examples
- Create tutorials
- Improve API documentation

### 4. Fix Bugs
- Check GitHub Issues for reported bugs
- Submit fixes with tests
- Include description of the fix

### 5. Add Features
- Propose new features via GitHub Issues first
- Implement with backward compatibility
- Include comprehensive tests
- Update documentation

## 🚀 Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/PyTeal-Checker.git
   cd PyTeal-Checker
   ```

2. **Run Setup Script**
   ```bash
   ./setup.sh
   ```

3. **Activate Virtual Environment**
   ```bash
   source venv/bin/activate
   ```

4. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 📝 Code Style Guidelines

### Python Code
- Follow PEP 8 style guide
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Keep functions focused and concise
- Add type hints where appropriate

### Example:
```python
def analyze_contract(self, code: str) -> AnalysisResult:
    """
    Perform comprehensive analysis on a PyTeal contract

    Args:
        code: The PyTeal smart contract code

    Returns:
        AnalysisResult with complete analysis
    """
    # Implementation here
    pass
```

### Testing
- Write tests for all new features
- Maintain or improve test coverage
- Use descriptive test names
- Include edge cases

### Example Test:
```python
def test_rekey_vulnerability_detection(self):
    """Test detection of rekey vulnerability"""
    vulnerable_code = '''
    from pyteal import *
    def vulnerable():
        return Return(Int(1))
    '''
    is_secure, issues, report = self.analyzer.analyze(vulnerable_code)
    self.assertFalse(is_secure)
    rekey_issues = [i for i in issues if 'rekey' in i.description.lower()]
    self.assertTrue(len(rekey_issues) > 0)
```

## 🧪 Testing

Run tests before submitting:

```bash
cd PyTealChecker
python manage.py test mainapp
```

Run specific test files:
```bash
python manage.py test mainapp.test_security_analyzer
python manage.py test mainapp.test_ml_model
python manage.py test mainapp.test_analysis_service
```

## 📤 Submitting Changes

1. **Ensure Tests Pass**
   ```bash
   python manage.py test mainapp
   ```

2. **Check Code Style**
   ```bash
   flake8 mainapp --max-line-length=127
   ```

3. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: Add XYZ feature"
   ```

   Use conventional commit messages:
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `test:` Test additions/changes
   - `refactor:` Code refactoring
   - `style:` Code style changes
   - `chore:` Maintenance tasks

4. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create Pull Request**
   - Go to GitHub and create a PR
   - Describe your changes clearly
   - Reference any related issues
   - Wait for review

## 🔍 Pull Request Review Process

1. **Automated Checks**: GitHub Actions will run tests
2. **Code Review**: Maintainers review your code
3. **Feedback**: Address any requested changes
4. **Approval**: Once approved, changes will be merged

## 🐛 Reporting Bugs

When reporting bugs, include:

1. **Description**: Clear description of the bug
2. **Steps to Reproduce**: Exact steps to reproduce the issue
3. **Expected Behavior**: What should happen
4. **Actual Behavior**: What actually happens
5. **Code Sample**: PyTeal code that triggers the bug (if applicable)
6. **Environment**: Python version, OS, etc.

### Example Bug Report:

```markdown
**Description**
Security analyzer fails to detect missing fee validation

**Steps to Reproduce**
1. Submit contract with no fee check
2. Review analysis results
3. No issue reported for missing fee validation

**Expected Behavior**
Should report high severity issue for missing fee validation

**Code Sample**
\`\`\`python
from pyteal import *
def test():
    return Return(Int(1))
\`\`\`

**Environment**
- Python 3.9
- Ubuntu 22.04
- PyTeal-Checker v2.0
```

## 💡 Feature Requests

For feature requests, please:

1. Check existing issues to avoid duplicates
2. Provide clear description of the feature
3. Explain the use case and benefits
4. Include examples if possible

## 📋 Adding Security Checks

When adding new security checks:

1. **Identify the Vulnerability**
   - Research the security issue
   - Understand common patterns
   - Document real-world examples

2. **Implement Detection**
   ```python
   def _check_your_vulnerability(self, code: str):
       """Check for XYZ vulnerability"""
       if vulnerable_pattern_found:
           self.issues.append(SecurityIssue(
               severity='high',  # critical, high, medium, low, info
               category='Category Name',
               description='Clear description of the issue',
               line_number=line_num,
               suggestion='How to fix it'
           ))
   ```

3. **Add Tests**
   ```python
   def test_your_vulnerability(self):
       """Test detection of XYZ vulnerability"""
       vulnerable_code = '''...'''
       is_secure, issues, report = self.analyzer.analyze(vulnerable_code)
       # Assert expected behavior
   ```

4. **Update Documentation**
   - Add to README feature list
   - Update API documentation
   - Add examples if needed

## 🎓 Learning Resources

- [PyTeal Documentation](https://pyteal.readthedocs.io/)
- [Algorand Developer Portal](https://developer.algorand.org/)
- [Smart Contract Security Best Practices](https://developer.algorand.org/docs/get-details/dapps/smart-contracts/guidelines/)

## 📜 Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the code, not the person
- Help create a welcoming community

## ❓ Questions?

If you have questions:
- Open a GitHub Issue
- Check existing documentation
- Review closed issues for similar questions

## 🙏 Recognition

Contributors will be recognized in:
- README contributors section
- Release notes
- GitHub contributors page

Thank you for helping improve PyTeal-Checker!
