# Security Assessment Management Report

**Assessment Date:** 2024-02-15
**Organisation:** Acme Corporation
**Total Findings:** 6
**Generated:** 12/09/2025, 09:49:22


## Executive Summary

| Metric | Value |
|--------|-------|
| Total Findings | 6 |
| Critical Findings | 1 |
| Technical Debt | 3.85 |
| Remediation Effort | 112.5 person-days |
| Security Maturity | 0% |
| Average Risk | 6.8/10 |

### Key Insights
- Significant remediation effort of 112.5 person-days needed
- Low security maturity index of 0% indicates insufficient controls
- 1 critical vulnerabilities pose immediate risk

### Top Recommendations
- Prioritise remediation of critical and high-severity vulnerabilities
- Implement additional security controls to improve maturity index
- Develop comprehensive remediation timeline based on effort estimates
- Establish regular vulnerability assessment schedule


## Technical Debt Analysis

**Total Technical Debt:** 3.85  
**Average per Vulnerability:** 0.64

### Debt by Severity
- **Low:** 0.00
- **Medium:** 0.76
- **High:** 2.15
- **Critical:** 0.95


## Remediation Effort Analysis

**Total Effort:** 112.5 person-days  
**Average per Vulnerability:** 18.7 person-days

### Effort by Complexity
- **Low:** 0.0 person-days
- **Medium:** 4.2 person-days
- **High:** 108.3 person-days

### Resource Requirements
- **Person Days:** 112
- **Team Weeks:** 22
- **Team Months:** 6
- **Recommended Team Size:** 4


## Dynamic Risk Matrix

### Critical-High (0 vulnerabilities)


### Critical-Medium (0 vulnerabilities)


### High-High (0 vulnerabilities)


### High-Medium (0 vulnerabilities)


### Medium-Medium (3 vulnerabilities)
- SQL Injection in Login Form (Likelihood: 0.93, Impact: 0.56)
- Buffer Overflow in Legacy Service (Likelihood: 0.9, Impact: 0.56)
- Privilege Escalation via Service (Likelihood: 0.9, Impact: 0.56)

### Medium-Low (0 vulnerabilities)


### Low-Low (3 vulnerabilities)
- Cross-Site Scripting (XSS) (Likelihood: NaN, Impact: 0.15)
- Information Disclosure in Logs (Likelihood: NaN, Impact: 0.07)
- Denial of Service via Resource Exhaustion (Likelihood: 0.93, Impact: 0.19)




## Compliance Mapping

### PCI Compliance
- **Compliance Score:** 17%
- **Compliant Vulnerabilities:** 1
- **Non-Compliant Vulnerabilities:** 5

#### Violations by Requirement
- **Requirement 6.1:** 4 violations
- **Requirement 6.2:** 3 violations
- **Requirement 11.2:** 4 violations

### SOX Compliance
- **Compliance Score:** 0%
- **Compliant Vulnerabilities:** 0
- **Non-Compliant Vulnerabilities:** 6

#### Violations by Requirement
- **Financial Data Integrity:** 3 violations
- **System Availability:** 4 violations
- **Access Controls:** 6 violations

### HIPAA Compliance
- **Compliance Score:** 33%
- **Compliant Vulnerabilities:** 2
- **Non-Compliant Vulnerabilities:** 4

#### Violations by Requirement
- **Data Confidentiality:** 3 violations
- **Data Integrity:** 3 violations
- **System Availability:** 4 violations




## Security Posture Analysis

- **Average Risk Score:** 6.85/10
- **Network Exposure Score:** 5.37/10
- **Privilege Risk Score:** 5.37/10
- **Security Maturity Index:** 0%
- **Controlled Vulnerabilities:** 0/6

### Risk Distribution
- **Low:** 0 vulnerabilities
- **Medium:** 3 vulnerabilities
- **High:** 2 vulnerabilities
- **Critical:** 1 vulnerabilities


## Mathematical Appendix

### Technical Debt Calculation
```
TD = Σ(VI × TDF × EF × AC)
```

Where:
- VI = Vulnerability Impact = (VC + VI + VA) / 3
- TDF = Time Decay Factor = 1 + (Days_Since_Disclosure / 365) × 0.1
- EF = Exploitability Factor = (AV + AC + AT) / 3
- AC = Asset Criticality (1.0-5.0)

### Remediation Effort Calculation
```
FE = BE × CM × TE × A
```

Where:
- FE = Final Effort (person-days)
- BE = Base Effort (based on CVSS score)
- CM = Complexity Multiplier (product of component multipliers)
- TE = Team Efficiency (0.7-1.3)
- A = Availability (0.8-1.0)

### Risk Matrix Calculation
```
L = (ES + TF) / 2
```

Where:
- L = Likelihood (0-1)
- ES = Exploitability Score = (AV + AC + AT + PR + UI) / 5
- TF = Temporal Factors = (E + AU + R) / 3

### Security Posture Calculation
```
SMI = (Controlled_Vulns / Total_Vulns) × 100
```

Where Controlled_Vulns = vulnerabilities where AC=H AND PR=H AND UI=A

