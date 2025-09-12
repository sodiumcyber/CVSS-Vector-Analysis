# CVSS-Based Management Metrics: Mathematical Formulas Reference

## Table of Contents
1. [CVSS Component Weights](#cvss-component-weights)
2. [Technical Debt Formulas](#technical-debt-formulas)
3. [Remediation Effort Formulas](#remediation-effort-formulas)
4. [Risk Matrix Calculations](#risk-matrix-calculations)
5. [Compliance Mapping Formulas](#compliance-mapping-formulas)
6. [Security Posture Metrics](#security-posture-metrics)
7. [Advanced Analytics](#advanced-analytics)

## CVSS Component Weights

### Base Score Components (CVSS 4.0)
```
Attack Vector (AV):
- Network (N): 0.85
- Adjacent (A): 0.60
- Local (L): 0.55
- Physical (P): 0.20

Attack Complexity (AC):
- Low (L): 0.77
- High (H): 0.44

Attack Requirements (AT):
- None (N): 0.85
- Present (P): 0.62

Privileges Required (PR):
- None (N): 0.85
- Low (L): 0.62
- High (H): 0.27

User Interaction (UI):
- None (N): 0.85
- Passive (P): 0.62
- Active (A): 0.45

Impact Components:
- Confidentiality (VC): High=0.56, Low=0.22, None=0
- Integrity (VI): High=0.56, Low=0.22, None=0
- Availability (VA): High=0.56, Low=0.22, None=0
```

### Temporal Components
```
Security Requirements (S):
- Not Defined (N): 1.0
- Low (L): 0.9
- Medium (M): 1.0
- High (H): 1.1

Exploit Maturity (E):
- Unreported (U): 1.0
- Proof of Concept (P): 1.0
- Attacked (A): 1.0
- Not Defined (X): 1.0

Automatable (AU):
- No (N): 1.0
- Yes (Y): 1.0
- Not Defined (X): 1.0

Recovery (R):
- None (N): 1.1
- User (U): 1.05
- Automatic (A): 0.95
- Not Defined (X): 1.0
```

## Technical Debt Formulas

### Primary Technical Debt Calculation
```
TD = Σ(VI × TDF × EF × AC)
```

Where:
- **TD** = Total Technical Debt
- **VI** = Vulnerability Impact
- **TDF** = Time Decay Factor
- **EF** = Exploitability Factor
- **AC** = Asset Criticality

### Vulnerability Impact (VI)
```
VI = (VC + VI + VA) / 3
```

Where VC, VI, VA are normalized impact scores (0-1).

### Time Decay Factor (TDF)
```
TDF = 1 + (D / 365) × 0.1
```

Where:
- **D** = Days since disclosure
- Maximum TDF = 2.0 (capped at 10 years)

### Exploitability Factor (EF)
```
EF = (AV + AC + AT) / 3
```

Where AV, AC, AT are normalized exploitability scores (0-1).

### Technical Debt by Severity
```
TD_severity = Σ(TD_i) for all vulnerabilities i where severity_i = severity
```

### Technical Debt Trend
```
Trend = (Recent_Vulns - Older_Vulns) / Total_Vulns
```

Where:
- Recent_Vulns = vulnerabilities disclosed in last 6 months
- Older_Vulns = vulnerabilities disclosed more than 6 months ago

## Remediation Effort Formulas

### Base Effort Calculation
```
BE = f(CVSS_Score)
```

Where:
- BE = Base Effort (person-days)
- f(9.0-10.0) = 15 days
- f(7.0-8.9) = 8 days
- f(4.0-6.9) = 4 days
- f(0.0-3.9) = 2 days

### Complexity Multiplier
```
CM = ∏(M_i) for all applicable metrics i
```

Where M_i are individual metric multipliers:
```
M_AV = {P: 0.5, L: 0.8, A: 1.2, N: 1.5}
M_AC = {H: 0.7, L: 1.3}
M_PR = {H: 0.6, L: 1.0, N: 1.4}
M_UI = {A: 0.8, P: 1.0, N: 1.2}
M_S = {U: 1.0, C: 1.5}
```

### Final Effort Calculation
```
FE = BE × CM × TE × A
```

Where:
- **FE** = Final Effort (person-days)
- **BE** = Base Effort
- **CM** = Complexity Multiplier
- **TE** = Team Efficiency (0.7-1.3)
- **A** = Availability (0.8-1.0)

### Resource Requirements
```
Person_Days = Σ(FE_i) for all vulnerabilities i
Team_Weeks = Person_Days / 5
Team_Months = Person_Days / 20
Recommended_Team_Size = ceil(Person_Days / 30)
```

## Risk Matrix Calculations

### Likelihood Calculation
```
L = (ES + TF) / 2
```

Where:
- **L** = Likelihood (0-1)
- **ES** = Exploitability Score
- **TF** = Temporal Factors

### Exploitability Score (ES)
```
ES = (AV + AC + AT + PR + UI) / 5
```

### Temporal Factors (TF)
```
TF = (E + AU + R) / 3
```

### Impact Calculation
```
I = (VC + VI + VA) / 3
```

### Risk Level Determination
```
Risk_Level = f(L, I)
```

Where:
- f(≥0.8, ≥0.8) = "Critical-High"
- f(≥0.6, ≥0.8) = "Critical-Medium"
- f(≥0.8, ≥0.6) = "High-High"
- f(≥0.6, ≥0.6) = "High-Medium"
- f(≥0.4, ≥0.4) = "Medium-Medium"
- f(≥0.4, ≥0.2) = "Medium-Low"
- f(<0.4, <0.2) = "Low-Low"

## Compliance Mapping Formulas

### Compliance Score
```
CS = (Compliant_Vulns / Total_Vulns) × 100
```

### Violation Count by Requirement
```
V_req = Σ(1) for all vulnerabilities where requirement_req(vuln) = true
```

### Compliance Trend
```
CT = (CS_current - CS_previous) / CS_previous × 100
```

### Risk-Weighted Compliance Score
```
RWCS = Σ(CVSS_i × Compliance_i) / Σ(CVSS_i)
```

Where Compliance_i = 1 if compliant, 0 if not.

## Security Posture Metrics

### Average Risk Score
```
ARS = Σ(CVSS_i) / n
```

Where n = total number of vulnerabilities.

### Network Exposure Score
```
NES = Σ(CVSS_i × NF_i) / n
```

Where NF_i = Network Factor for vulnerability i:
- NF = 1.0 if AV=N
- NF = 0.5 if AV=A
- NF = 0.2 if AV=L
- NF = 0.1 if AV=P

### Privilege Escalation Risk
```
PER = Σ(CVSS_i × PF_i) / n
```

Where PF_i = Privilege Factor for vulnerability i:
- PF = 1.0 if PR=N
- PF = 0.6 if PR=L
- PF = 0.2 if PR=H

### Security Maturity Index
```
SMI = (Controlled_Vulns / Total_Vulns) × 100
```

Where Controlled_Vulns = vulnerabilities where AC=H AND PR=H AND UI=A.

### Attack Surface Score
```
ASS = Σ(CVSS_i × ASF_i) / n
```

Where ASF_i = Attack Surface Factor:
- ASF = 1.0 if AV=N AND AC=L
- ASF = 0.7 if AV=A AND AC=L
- ASF = 0.4 if AV=L AND AC=H
- ASF = 0.1 if AV=P

## Advanced Analytics

### Vulnerability Clustering Similarity
```
Similarity(A, B) = Σ(w_i × |A_i - B_i|) / Σ(w_i)
```

Where:
- A, B = CVSS vectors
- w_i = weight for component i
- A_i, B_i = normalized values for component i

### Risk Velocity
```
RV = (New_Risk - Remediated_Risk) / Time_Period
```

Where:
- New_Risk = Σ(CVSS_i) for new vulnerabilities
- Remediated_Risk = Σ(CVSS_i) for remediated vulnerabilities

### Risk Accumulation Rate
```
RAR = Σ(CVSS_i × TW_i) / Time_Period
```

Where TW_i = Time Weight for vulnerability i:
- TW = 1.0 + (Days_Old / 365) × 0.1

### Predictive Risk Projection
```
PRP = Current_Risk × (1 + GR)^TH
```

Where:
- GR = Growth Rate (calculated from historical data)
- TH = Time Horizon (in years)

### Vulnerability Density
```
VD = Total_Vulns / Asset_Count
```

### Risk Concentration Index
```
RCI = Σ(CVSS_i^2) / (Σ(CVSS_i))^2
```

Values closer to 1 indicate high concentration of risk in few vulnerabilities.

### Remediation Efficiency
```
RE = Remediated_Effort / Planned_Effort × 100
```

### Security Debt Interest Rate
```
SDIR = (Current_Debt - Previous_Debt) / Previous_Debt × 100
```

### Compliance Drift Rate
```
CDR = (Current_Compliance - Baseline_Compliance) / Baseline_Compliance × 100
```

## Statistical Measures

### Risk Distribution Variance
```
σ² = Σ(CVSS_i - μ)² / n
```

Where μ = mean CVSS score.

### Risk Skewness
```
Skewness = Σ(CVSS_i - μ)³ / (n × σ³)
```

### Risk Kurtosis
```
Kurtosis = Σ(CVSS_i - μ)⁴ / (n × σ⁴) - 3
```

### Correlation with Business Impact
```
r = Σ((CVSS_i - μ_CVSS) × (BI_i - μ_BI)) / √(Σ(CVSS_i - μ_CVSS)² × Σ(BI_i - μ_BI)²)
```

Where BI_i = Business Impact score for vulnerability i.

## Implementation Notes

### Normalization
All CVSS component values should be normalized to 0-1 scale before calculations:
```
Normalized_Value = (Raw_Value - Min_Value) / (Max_Value - Min_Value)
```

### Rounding
- Final scores should be rounded to 2 decimal places
- Percentages should be rounded to whole numbers
- Effort estimates should be rounded to nearest 0.5 person-days

### Validation
- All calculations should include bounds checking
- Negative values should be handled appropriately
- Division by zero should be prevented

### Performance Considerations
- Use efficient data structures for large vulnerability datasets
- Consider caching for frequently calculated metrics
- Implement incremental updates for real-time dashboards
