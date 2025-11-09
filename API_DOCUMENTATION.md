# PyTeal-Checker REST API Documentation

## Overview

The PyTeal-Checker REST API provides programmatic access to comprehensive PyTeal smart contract security analysis. All endpoints return JSON responses.

**Base URL:** `http://localhost:8000` (development) or your deployed URL

## Endpoints

### 1. Analyze Contract

Performs comprehensive security analysis on a PyTeal smart contract.

**Endpoint:** `POST /api/analyze`

**Request Headers:**
```
Content-Type: application/json
```

**Request Body:**
```json
{
  "code": "from pyteal import *\n\ndef approval():\n    return Return(Int(1))"
}
```

**Response (Success - 200 OK):**
```json
{
  "success": true,
  "analysis": {
    "is_secure": false,
    "security_score": 45,
    "risk_level": "high",
    "ml_prediction": "0",
    "ml_confidence": 0.85,
    "secure_probability": 0.15,
    "insecure_probability": 0.85,
    "total_issues": 5,
    "critical_issues": 2,
    "high_issues": 1,
    "medium_issues": 2,
    "low_issues": 0,
    "info_issues": 0,
    "issues": [
      {
        "severity": "critical",
        "category": "Rekey Vulnerability",
        "description": "Missing rekey_to validation - attacker can change account authorization",
        "line_number": 3,
        "suggestion": "Add: Txn.rekey_to() == Global.zero_address()"
      }
    ],
    "lines_of_code": 15,
    "contract_type": "Stateful Application",
    "features": {
      "has_pyteal_import": true,
      "has_authorization": false,
      "has_fee_validation": false,
      "has_rekey_protection": false,
      "has_close_protection": false
    },
    "is_production_ready": false,
    "recommendations": [
      "CRITICAL: Address 2 critical security issues before deployment",
      "Add rekey_to validation to prevent account takeover",
      "Add close_remainder_to validation to prevent fund drainage"
    ]
  }
}
```

**Response (Error - 400 Bad Request):**
```json
{
  "error": "No code provided",
  "message": "Please provide PyTeal code in the 'code' field"
}
```

**Response (Error - 500 Internal Server Error):**
```json
{
  "error": "Analysis failed",
  "message": "Error details here"
}
```

**Example using cURL:**
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "code": "from pyteal import *\n\ndef approval():\n    fee_cond = Txn.fee() < Int(1000)\n    safety_cond = And(\n        Txn.type_enum() == TxnType.Payment,\n        Txn.close_remainder_to() == Global.zero_address(),\n        Txn.rekey_to() == Global.zero_address()\n    )\n    return And(fee_cond, safety_cond)"
  }'
```

**Example using Python:**
```python
import requests
import json

url = "http://localhost:8000/api/analyze"
code = """
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
"""

response = requests.post(url, json={"code": code})
result = response.json()

print(f"Security Score: {result['analysis']['security_score']}/100")
print(f"Production Ready: {result['analysis']['is_production_ready']}")
print(f"Total Issues: {result['analysis']['total_issues']}")
```

**Example using JavaScript:**
```javascript
const analyzeContract = async (code) => {
  const response = await fetch('http://localhost:8000/api/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ code }),
  });

  const result = await response.json();
  return result.analysis;
};

// Usage
const code = `
from pyteal import *

def approval():
    return Return(Int(1))
`;

analyzeContract(code).then(analysis => {
  console.log(`Security Score: ${analysis.security_score}/100`);
  console.log(`Risk Level: ${analysis.risk_level}`);
});
```

---

### 2. Health Check

Checks if the API service is running and healthy.

**Endpoint:** `GET /api/health`

**Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "PyTeal-Checker API",
  "version": "2.0"
}
```

**Example using cURL:**
```bash
curl http://localhost:8000/api/health
```

---

### 3. Get Features

Returns a list of all security features and checks performed by the analyzer.

**Endpoint:** `GET /api/features`

**Response (200 OK):**
```json
{
  "security_checks": [
    "Rekey vulnerability detection",
    "Close remainder vulnerability detection",
    "Fee validation",
    "Authorization checks",
    "Arithmetic safety",
    "Time manipulation resistance",
    "Randomness security",
    "Delete/Update permission validation",
    "Asset transfer validation",
    "Group transaction validation",
    "Input validation",
    "Reentrancy pattern detection"
  ],
  "ml_features": [
    "Text-based pattern recognition",
    "Feature extraction (30+ features)",
    "Ensemble classification",
    "Confidence scoring"
  ],
  "code_metrics": [
    "Lines of code",
    "Contract type detection",
    "Function count",
    "Security score (0-100)",
    "Production readiness assessment"
  ]
}
```

**Example using cURL:**
```bash
curl http://localhost:8000/api/features
```

---

## Response Field Descriptions

### Analysis Result Fields

| Field | Type | Description |
|-------|------|-------------|
| `is_secure` | boolean | Whether the contract is considered secure |
| `security_score` | integer | Overall security score (0-100) |
| `risk_level` | string | Risk assessment: "critical", "high", "medium", "low", "minimal" |
| `ml_prediction` | string | ML model prediction: "1" (secure) or "0" (insecure) |
| `ml_confidence` | float | ML model confidence (0.0-1.0) |
| `secure_probability` | float | Probability contract is secure (0.0-1.0) |
| `insecure_probability` | float | Probability contract is insecure (0.0-1.0) |
| `total_issues` | integer | Total number of issues found |
| `critical_issues` | integer | Number of critical severity issues |
| `high_issues` | integer | Number of high severity issues |
| `medium_issues` | integer | Number of medium severity issues |
| `low_issues` | integer | Number of low severity issues |
| `info_issues` | integer | Number of informational items |
| `issues` | array | Detailed list of all issues |
| `lines_of_code` | integer | Number of lines in the contract |
| `contract_type` | string | Detected contract type |
| `features` | object | Dictionary of detected features |
| `is_production_ready` | boolean | Whether contract is ready for production |
| `recommendations` | array | List of actionable recommendations |

### Issue Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `severity` | string | Issue severity: "critical", "high", "medium", "low", "info" |
| `category` | string | Category of the issue |
| `description` | string | Detailed description of the issue |
| `line_number` | integer | Line number where issue occurs (if applicable) |
| `suggestion` | string | Recommended fix |

---

## Security Score Interpretation

| Score Range | Interpretation | Action |
|-------------|---------------|--------|
| 90-100 | Excellent | Minor improvements, professional audit recommended |
| 80-89 | Good | Address medium/low issues, professional audit recommended |
| 70-79 | Fair | Fix high severity issues before production |
| 50-69 | Poor | Significant security issues, major refactoring needed |
| 0-49 | Critical | DO NOT DEPLOY - fundamental security flaws |

---

## Rate Limiting

Currently, there are no rate limits on the API. For production deployments, consider implementing rate limiting based on your infrastructure.

---

## Error Handling

All error responses follow this format:
```json
{
  "error": "Error type",
  "message": "Detailed error message"
}
```

Common HTTP status codes:
- `200 OK` - Request successful
- `400 Bad Request` - Invalid request (missing code, invalid JSON)
- `500 Internal Server Error` - Server error during analysis

---

## Best Practices

1. **Always check `is_production_ready`** before deploying contracts
2. **Review all critical and high severity issues** immediately
3. **Use the security_score** as a general indicator, not absolute truth
4. **Read the recommendations** for actionable next steps
5. **Get professional audits** for production contracts regardless of score
6. **Test on TestNet** before MainNet deployment

---

## Integration Examples

### CI/CD Pipeline (GitHub Actions)

```yaml
- name: Analyze PyTeal Contract
  run: |
    response=$(curl -s -X POST http://your-server/api/analyze \
      -H "Content-Type: application/json" \
      -d @contract.json)

    score=$(echo $response | jq '.analysis.security_score')

    if [ $score -lt 80 ]; then
      echo "Security score too low: $score"
      exit 1
    fi
```

### Python Integration

```python
class PyTealChecker:
    def __init__(self, api_url="http://localhost:8000"):
        self.api_url = api_url

    def analyze(self, code):
        response = requests.post(
            f"{self.api_url}/api/analyze",
            json={"code": code}
        )
        response.raise_for_status()
        return response.json()['analysis']

    def is_production_ready(self, code):
        analysis = self.analyze(code)
        return (
            analysis['is_production_ready'] and
            analysis['security_score'] >= 80 and
            analysis['critical_issues'] == 0
        )
```

---

## Support

For issues, questions, or feature requests:
- GitHub Issues: https://github.com/jakobrichert/PyTeal-Checker/issues
- Documentation: See README.md

---

**Version:** 2.0
**Last Updated:** 2024
