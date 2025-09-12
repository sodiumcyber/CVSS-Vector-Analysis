/**
 * Campbell Murray - Sodium Cyber Ltd - 2025
 * CVSS Management Metrics Report Generator
 * 
 * Generates comprehensive management reports and appendices with CVSS-based
 * calculations for technical debt, risk analysis, compliance, and remediation planning.
 */

// Import the CVSSMetricsCalculator
const CVSSMetricsCalculator = require('./CVSS_Metrics_Implementation.js');

class CVSSReportGenerator {
    constructor() {
        this.calculator = new CVSSMetricsCalculator();
        this.reportData = null;
        this.templateData = {
            reportTitle: 'Security Assessment Management Report',
            assessmentDate: new Date().toISOString().split('T')[0],
            organisation: 'Organisation Name',
            assessor: 'Security Assessment Team',
            reportVersion: '1.0'
        };
    }

    /**
     * Convert findings data to the format expected by CVSSMetricsCalculator
     * @param {Array} findings - Array of vulnerability findings
     * @returns {Array} Converted vulnerability data
     */
    convertFindingsToVulnerabilities(findings) {
        return findings.map(finding => ({
            id: finding.id || `finding-${Math.random().toString(36).substr(2, 9)}`,
            title: finding.title || finding.Title || 'Unknown Vulnerability',
            cvssScore: finding.CVSS || finding.cvssScore || '0.0',
            vector: finding.CVSSVector || finding.vector || 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/S:U/E:U/AU:N/R:U',
            disclosureDate: finding.disclosureDate || finding.Date || new Date().toISOString().split('T')[0],
            category: finding.category || finding.Category || 'Unknown',
            asset: finding.asset || finding.Asset || 'Unknown Asset'
        }));
    }

    /**
     * Generate comprehensive management report
     * @param {Array} findings - Array of vulnerability findings
     * @param {Object} options - Report generation options
     * @returns {Object} Complete report data
     */
    generateManagementReport(findings, options = {}) {
        console.log('CVSSReportGenerator: Generating management report...');
        
        // Convert findings to vulnerability format
        const vulnerabilities = this.convertFindingsToVulnerabilities(findings);
        
        // Merge options with defaults
        const reportOptions = {
            includeTechnicalDebt: true,
            includeRemediationEffort: true,
            includeRiskMatrix: true,
            includeComplianceMapping: true,
            includeSecurityPosture: true,
            includeVulnerabilityClustering: true,
            includeExecutiveSummary: true,
            assetCriticality: 2.0,
            teamEfficiency: 1.0,
            complianceFrameworks: ['PCI', 'SOX', 'HIPAA'],
            ...options
        };

        // Calculate all metrics using converted vulnerability data
        const technicalDebt = reportOptions.includeTechnicalDebt ? 
            this.calculator.calculateTechnicalDebt(vulnerabilities, reportOptions.assetCriticality) : null;
        
        const remediationEffort = reportOptions.includeRemediationEffort ? 
            this.calculator.calculateRemediationEffort(vulnerabilities, reportOptions.teamEfficiency) : null;
        
        const riskMatrix = reportOptions.includeRiskMatrix ? 
            this.calculator.generateRiskMatrix(vulnerabilities) : null;
        
        const complianceMapping = reportOptions.includeComplianceMapping ? 
            this.generateComplianceMapping(vulnerabilities, reportOptions.complianceFrameworks) : null;
        
        const securityPosture = reportOptions.includeSecurityPosture ? 
            this.calculator.calculateSecurityPosture(vulnerabilities) : null;
        
        const vulnerabilityClustering = reportOptions.includeVulnerabilityClustering ? 
            this.calculator.clusterVulnerabilities(vulnerabilities, 0.7) : null;

        // Generate executive summary
        const executiveSummary = reportOptions.includeExecutiveSummary ? 
            this.generateExecutiveSummary(vulnerabilities, {
                technicalDebt,
                remediationEffort,
                riskMatrix,
                complianceMapping,
                securityPosture
            }) : null;

        // Compile report data
        this.reportData = {
            metadata: {
                ...this.templateData,
                generatedAt: new Date().toISOString(),
                totalFindings: findings.length,
                reportOptions
            },
            executiveSummary,
            technicalDebt,
            remediationEffort,
            riskMatrix,
            complianceMapping,
            securityPosture,
            vulnerabilityClustering,
            detailedAnalysis: this.generateDetailedAnalysis(findings),
            recommendations: this.generateRecommendations(findings, {
                technicalDebt,
                remediationEffort,
                riskMatrix,
                complianceMapping,
                securityPosture
            })
        };

        return this.reportData;
    }

    /**
     * Generate HTML report for display/export
     * @param {Object} reportData - Report data from generateManagementReport
     * @param {string} format - Output format ('html', 'markdown', 'text')
     * @returns {string} Formatted report
     */
    generateFormattedReport(reportData = null, format = 'html') {
        const data = reportData || this.reportData;
        if (!data) {
            throw new Error('No report data available. Generate report first.');
        }

        switch (format.toLowerCase()) {
            case 'html':
                return this.generateHTMLReport(data);
            case 'markdown':
                return this.generateMarkdownReport(data);
            case 'text':
                return this.generateTextReport(data);
            default:
                throw new Error(`Unsupported format: ${format}`);
        }
    }

    /**
     * Generate HTML report
     */
    generateHTMLReport(data) {
        const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${data.metadata.reportTitle}</title>
    <style>
        ${this.getReportStyles()}
    </style>
</head>
<body>
    <div class="report-container">
        ${this.generateReportHeader(data.metadata)}
        ${data.executiveSummary ? this.generateExecutiveSummaryHTML(data.executiveSummary) : ''}
        ${data.technicalDebt ? this.generateTechnicalDebtHTML(data.technicalDebt) : ''}
        ${data.remediationEffort ? this.generateRemediationEffortHTML(data.remediationEffort) : ''}
        ${data.riskMatrix ? this.generateRiskMatrixHTML(data.riskMatrix) : ''}
        ${data.complianceMapping ? this.generateComplianceMappingHTML(data.complianceMapping) : ''}
        ${data.securityPosture ? this.generateSecurityPostureHTML(data.securityPosture) : ''}
        ${data.vulnerabilityClustering ? this.generateVulnerabilityClusteringHTML(data.vulnerabilityClustering) : ''}
        ${this.generateDetailedAnalysisHTML(data.detailedAnalysis)}
        ${this.generateRecommendationsHTML(data.recommendations)}
        ${this.generateMathematicalAppendix(data)}
    </div>
</body>
</html>`;
        return html;
    }

    /**
     * Generate Markdown report
     */
    generateMarkdownReport(data) {
        let markdown = `# ${data.metadata.reportTitle}\n\n`;
        markdown += `**Assessment Date:** ${data.metadata.assessmentDate}\n`;
        markdown += `**Organisation:** ${data.metadata.organisation}\n`;
        markdown += `**Total Findings:** ${data.metadata.totalFindings}\n`;
        markdown += `**Generated:** ${new Date(data.metadata.generatedAt).toLocaleString()}\n\n`;

        if (data.executiveSummary) {
            markdown += this.generateExecutiveSummaryMarkdown(data.executiveSummary);
        }

        if (data.technicalDebt) {
            markdown += this.generateTechnicalDebtMarkdown(data.technicalDebt);
        }

        if (data.remediationEffort) {
            markdown += this.generateRemediationEffortMarkdown(data.remediationEffort);
        }

        if (data.riskMatrix) {
            markdown += this.generateRiskMatrixMarkdown(data.riskMatrix);
        }

        if (data.complianceMapping) {
            markdown += this.generateComplianceMappingMarkdown(data.complianceMapping);
        }

        if (data.securityPosture) {
            markdown += this.generateSecurityPostureMarkdown(data.securityPosture);
        }

        markdown += this.generateMathematicalAppendixMarkdown(data);

        return markdown;
    }

    /**
     * Generate compliance mapping for multiple frameworks
     */
    generateComplianceMapping(findings, frameworks) {
        const mapping = {};
        
        frameworks.forEach(framework => {
            mapping[framework] = this.calculator.mapCompliance(findings, framework);
        });
        
        return mapping;
    }

    /**
     * Generate executive summary
     */
    generateExecutiveSummary(vulnerabilities, metrics) {
        const totalFindings = vulnerabilities.length;
        const criticalFindings = vulnerabilities.filter(v => parseFloat(v.cvssScore) >= 9.0).length;
        const highFindings = vulnerabilities.filter(v => parseFloat(v.cvssScore) >= 7.0 && parseFloat(v.cvssScore) < 9.0).length;
        
        return {
            totalFindings,
            criticalFindings,
            highFindings,
            technicalDebt: metrics.technicalDebt?.totalDebt || 0,
            remediationEffort: metrics.remediationEffort?.totalEffort || 0,
            securityMaturity: metrics.securityPosture?.maturityIndex || 0,
            averageRisk: metrics.securityPosture?.averageRisk || 0,
            complianceScores: this.calculateOverallCompliance(metrics.complianceMapping),
            keyInsights: this.generateKeyInsights(vulnerabilities, metrics),
            topRecommendations: this.generateTopRecommendations(vulnerabilities, metrics)
        };
    }

    /**
     * Generate detailed analysis
     */
    generateDetailedAnalysis(findings) {
        const analysis = {
            vulnerabilityDistribution: this.calculateVulnerabilityDistribution(findings),
            attackVectorAnalysis: this.calculateAttackVectorAnalysis(findings),
            impactAnalysis: this.calculateImpactAnalysis(findings),
            temporalAnalysis: this.calculateTemporalAnalysis(findings),
            assetAnalysis: this.calculateAssetAnalysis(findings)
        };
        
        return analysis;
    }

    /**
     * Generate recommendations
     */
    generateRecommendations(findings, metrics) {
        const recommendations = [];
        
        // Technical debt recommendations
        if (metrics.technicalDebt && metrics.technicalDebt.totalDebt > 5) {
            recommendations.push({
                category: 'Technical Debt',
                priority: 'High',
                title: 'Address High Technical Debt',
                description: `Current technical debt of ${metrics.technicalDebt.totalDebt.toFixed(2)} debt units requires immediate attention.`,
                action: 'Prioritise remediation of critical and high-severity vulnerabilities to reduce technical debt accumulation.'
            });
        }
        
        // Remediation effort recommendations
        if (metrics.remediationEffort && metrics.remediationEffort.totalEffort > 50) {
            recommendations.push({
                category: 'Resource Planning',
                priority: 'Medium',
                title: 'Increase Remediation Resources',
                description: `Remediation effort of ${metrics.remediationEffort.totalEffort} person-days exceeds current capacity.`,
                action: `Consider allocating additional resources or extending timeline to ${Math.ceil(metrics.remediationEffort.totalEffort / 20)} months.`
            });
        }
        
        // Security posture recommendations
        if (metrics.securityPosture && metrics.securityPosture.maturityIndex < 50) {
            recommendations.push({
                category: 'Security Maturity',
                priority: 'High',
                title: 'Improve Security Controls',
                description: `Security maturity index of ${metrics.securityPosture.maturityIndex}% indicates insufficient controls.`,
                action: 'Implement additional security controls to increase the number of well-controlled vulnerabilities.'
            });
        }
        
        // Compliance recommendations
        if (metrics.complianceMapping) {
            Object.keys(metrics.complianceMapping).forEach(framework => {
                const compliance = metrics.complianceMapping[framework];
                if (compliance.complianceScore < 70) {
                    recommendations.push({
                        category: 'Compliance',
                        priority: 'High',
                        title: `Improve ${framework} Compliance`,
                        description: `${framework} compliance score of ${compliance.complianceScore}% is below acceptable threshold.`,
                        action: `Address ${compliance.nonCompliantVulnerabilities} non-compliant vulnerabilities to meet ${framework} requirements.`
                    });
                }
            });
        }
        
        return recommendations;
    }

    // Helper methods for generating specific sections
    generateExecutiveSummaryHTML(summary) {
        return `
        <section class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="summary-metrics">
                <div class="metric-card">
                    <h3>Total Findings</h3>
                    <div class="metric-value">${summary.totalFindings}</div>
                </div>
                <div class="metric-card">
                    <h3>Critical Findings</h3>
                    <div class="metric-value critical">${summary.criticalFindings}</div>
                </div>
                <div class="metric-card">
                    <h3>Technical Debt</h3>
                    <div class="metric-value">${summary.technicalDebt.toFixed(2)}</div>
                </div>
                <div class="metric-card">
                    <h3>Remediation Effort</h3>
                    <div class="metric-value">${summary.remediationEffort.toFixed(1)} person-days</div>
                </div>
                <div class="metric-card">
                    <h3>Security Maturity</h3>
                    <div class="metric-value">${summary.securityMaturity}%</div>
                </div>
                <div class="metric-card">
                    <h3>Average Risk</h3>
                    <div class="metric-value">${summary.averageRisk.toFixed(1)}/10</div>
                </div>
            </div>
            <div class="key-insights">
                <h3>Key Insights</h3>
                <ul>
                    ${summary.keyInsights.map(insight => `<li>${insight}</li>`).join('')}
                </ul>
            </div>
        </section>`;
    }

    generateTechnicalDebtHTML(debt) {
        return `
        <section class="technical-debt">
            <h2>Technical Debt Analysis</h2>
            <div class="debt-metrics">
                <div class="metric-row">
                    <span class="metric-label">Total Technical Debt:</span>
                    <span class="metric-value">${debt.totalDebt}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Average per Vulnerability:</span>
                    <span class="metric-value">${debt.averageDebtPerVuln}</span>
                </div>
            </div>
            <div class="debt-breakdown">
                <h3>Debt by Severity</h3>
                <div class="breakdown-chart">
                    ${Object.entries(debt.debtBySeverity).map(([severity, amount]) => 
                        `<div class="breakdown-item">
                            <span class="severity">${severity}:</span>
                            <span class="amount">${amount.toFixed(2)}</span>
                        </div>`
                    ).join('')}
                </div>
            </div>
        </section>`;
    }

    generateMathematicalAppendix(data) {
        return `
        <section class="mathematical-appendix">
            <h2>Mathematical Appendix</h2>
            <div class="formulas">
                <h3>Technical Debt Calculation</h3>
                <div class="formula">
                    <code>TD = Σ(VI × TDF × EF × AC)</code>
                    <p>Where:<br>
                    VI = Vulnerability Impact = (VC + VI + VA) / 3<br>
                    TDF = Time Decay Factor = 1 + (Days_Since_Disclosure / 365) × 0.1<br>
                    EF = Exploitability Factor = (AV + AC + AT) / 3<br>
                    AC = Asset Criticality (1.0-5.0)</p>
                </div>
                
                <h3>Remediation Effort Calculation</h3>
                <div class="formula">
                    <code>FE = BE × CM × TE × A</code>
                    <p>Where:<br>
                    FE = Final Effort (person-days)<br>
                    BE = Base Effort (based on CVSS score)<br>
                    CM = Complexity Multiplier (product of component multipliers)<br>
                    TE = Team Efficiency (0.7-1.3)<br>
                    A = Availability (0.8-1.0)</p>
                </div>
                
                <h3>Risk Matrix Calculation</h3>
                <div class="formula">
                    <code>L = (ES + TF) / 2</code>
                    <p>Where:<br>
                    L = Likelihood (0-1)<br>
                    ES = Exploitability Score = (AV + AC + AT + PR + UI) / 5<br>
                    TF = Temporal Factors = (E + AU + R) / 3</p>
                </div>
                
                <h3>Security Posture Calculation</h3>
                <div class="formula">
                    <code>SMI = (Controlled_Vulns / Total_Vulns) × 100</code>
                    <p>Where Controlled_Vulns = vulnerabilities where AC=H AND PR=H AND UI=A</p>
                </div>
            </div>
        </section>`;
    }

    // Additional helper methods would be implemented here...
    // (generateRemediationEffortHTML, generateRiskMatrixHTML, etc.)

    getReportStyles() {
        return `
        .report-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
        }
        
        .executive-summary {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        
        .summary-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .metric-card {
            background: white;
            padding: 15px;
            border-radius: 6px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .metric-card h3 {
            margin: 0 0 10px 0;
            font-size: 14px;
            color: #666;
            text-transform: uppercase;
        }
        
        .metric-value {
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .metric-value.critical {
            color: #e74c3c;
        }
        
        .key-insights ul {
            margin: 0;
            padding-left: 20px;
        }
        
        .key-insights li {
            margin-bottom: 8px;
        }
        
        .technical-debt, .remediation-effort, .risk-matrix, .compliance-mapping, .security-posture {
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
        }
        
        .debt-metrics, .effort-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .metric-row {
            display: flex;
            justify-content: space-between;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
        }
        
        .metric-label {
            font-weight: 500;
        }
        
        .breakdown-chart {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
        }
        
        .breakdown-item {
            display: flex;
            justify-content: space-between;
            padding: 8px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        
        .mathematical-appendix {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-top: 30px;
        }
        
        .formulas {
            display: grid;
            gap: 20px;
        }
        
        .formula {
            background: white;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #3498db;
        }
        
        .formula code {
            display: block;
            background: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 16px;
            margin-bottom: 10px;
        }
        
        .formula p {
            margin: 0;
            font-size: 14px;
            color: #666;
        }
        
        h1, h2, h3 {
            color: #2c3e50;
        }
        
        h2 {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        `;
    }

    // Additional helper methods for calculations and formatting...
    calculateVulnerabilityDistribution(findings) {
        const distribution = { Low: 0, Medium: 0, High: 0, Critical: 0 };
        findings.forEach(finding => {
            const score = parseFloat(finding.CVSS) || 0;
            if (score >= 9.0) distribution.Critical++;
            else if (score >= 7.0) distribution.High++;
            else if (score >= 4.0) distribution.Medium++;
            else distribution.Low++;
        });
        return distribution;
    }

    calculateAttackVectorAnalysis(findings) {
        const vectors = { Network: 0, Adjacent: 0, Local: 0, Physical: 0, Unknown: 0 };
        findings.forEach(finding => {
            if (finding.CVSSVector) {
                const vector = finding.CVSSVector.toLowerCase();
                if (vector.includes('av:n')) vectors.Network++;
                else if (vector.includes('av:a')) vectors.Adjacent++;
                else if (vector.includes('av:l')) vectors.Local++;
                else if (vector.includes('av:p')) vectors.Physical++;
                else vectors.Unknown++;
            } else {
                vectors.Unknown++;
            }
        });
        return vectors;
    }

    calculateImpactAnalysis(findings) {
        const impacts = { Confidentiality: 0, Integrity: 0, Availability: 0 };
        findings.forEach(finding => {
            if (finding.CVSSVector) {
                const vector = finding.CVSSVector.toLowerCase();
                if (vector.includes('vc:h')) impacts.Confidentiality++;
                if (vector.includes('vi:h')) impacts.Integrity++;
                if (vector.includes('va:h')) impacts.Availability++;
            }
        });
        return impacts;
    }

    calculateTemporalAnalysis(findings) {
        const temporal = { Recent: 0, Older: 0 };
        const sixMonthsAgo = new Date();
        sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
        
        findings.forEach(finding => {
            if (finding.disclosureDate) {
                const disclosureDate = new Date(finding.disclosureDate);
                if (disclosureDate > sixMonthsAgo) {
                    temporal.Recent++;
                } else {
                    temporal.Older++;
                }
            } else {
                temporal.Older++;
            }
        });
        return temporal;
    }

    calculateAssetAnalysis(findings) {
        const assets = {};
        findings.forEach(finding => {
            const asset = finding.AffectedComponents || 'Unspecified';
            const primaryAsset = asset.split(/[,;\n]/)[0].trim() || 'Unspecified';
            assets[primaryAsset] = (assets[primaryAsset] || 0) + 1;
        });
        return assets;
    }

    calculateOverallCompliance(complianceMapping) {
        if (!complianceMapping) return {};
        const scores = {};
        Object.keys(complianceMapping).forEach(framework => {
            scores[framework] = complianceMapping[framework].complianceScore;
        });
        return scores;
    }

    generateKeyInsights(vulnerabilities, metrics) {
        const insights = [];
        
        if (metrics.technicalDebt && metrics.technicalDebt.totalDebt > 5) {
            insights.push(`High technical debt of ${metrics.technicalDebt.totalDebt.toFixed(2)} units requires immediate attention`);
        }
        
        if (metrics.remediationEffort && metrics.remediationEffort.totalEffort > 50) {
            insights.push(`Significant remediation effort of ${metrics.remediationEffort.totalEffort} person-days needed`);
        }
        
        if (metrics.securityPosture && metrics.securityPosture.maturityIndex < 50) {
            insights.push(`Low security maturity index of ${metrics.securityPosture.maturityIndex}% indicates insufficient controls`);
        }
        
        const criticalCount = vulnerabilities.filter(v => parseFloat(v.cvssScore) >= 9.0).length;
        if (criticalCount > 0) {
            insights.push(`${criticalCount} critical vulnerabilities pose immediate risk`);
        }
        
        return insights;
    }

    generateTopRecommendations(vulnerabilities, metrics) {
        const recommendations = [];
        
        recommendations.push('Prioritise remediation of critical and high-severity vulnerabilities');
        recommendations.push('Implement additional security controls to improve maturity index');
        recommendations.push('Develop comprehensive remediation timeline based on effort estimates');
        recommendations.push('Establish regular vulnerability assessment schedule');
        
        return recommendations;
    }

    // Additional helper methods for Markdown generation...
    generateExecutiveSummaryMarkdown(summary) {
        return `
## Executive Summary

| Metric | Value |
|--------|-------|
| Total Findings | ${summary.totalFindings} |
| Critical Findings | ${summary.criticalFindings} |
| Technical Debt | ${summary.technicalDebt.toFixed(2)} |
| Remediation Effort | ${summary.remediationEffort.toFixed(1)} person-days |
| Security Maturity | ${summary.securityMaturity}% |
| Average Risk | ${summary.averageRisk.toFixed(1)}/10 |

### Key Insights
${summary.keyInsights.map(insight => `- ${insight}`).join('\n')}

### Top Recommendations
${summary.topRecommendations.map(rec => `- ${rec}`).join('\n')}

`;
    }

    generateTechnicalDebtMarkdown(debt) {
        return `
## Technical Debt Analysis

**Total Technical Debt:** ${debt.totalDebt}  
**Average per Vulnerability:** ${debt.averageDebtPerVuln}

### Debt by Severity
${Object.entries(debt.debtBySeverity).map(([severity, amount]) => 
    `- **${severity}:** ${amount.toFixed(2)}`
).join('\n')}

`;
    }

    generateRemediationEffortMarkdown(effort) {
        return `
## Remediation Effort Analysis

**Total Effort:** ${effort.totalEffort} person-days  
**Average per Vulnerability:** ${effort.averageEffortPerVuln} person-days

### Effort by Complexity
${Object.entries(effort.effortByComplexity).map(([complexity, amount]) => 
    `- **${complexity}:** ${amount.toFixed(1)} person-days`
).join('\n')}

### Resource Requirements
- **Person Days:** ${effort.resourceRequirements.personDays}
- **Team Weeks:** ${effort.resourceRequirements.teamWeeks}
- **Team Months:** ${effort.resourceRequirements.teamMonths}
- **Recommended Team Size:** ${effort.resourceRequirements.recommendedTeamSize}

`;
    }

    generateRiskMatrixMarkdown(riskMatrix) {
        return `
## Dynamic Risk Matrix

${Object.entries(riskMatrix).map(([riskLevel, vulnerabilities]) => 
    `### ${riskLevel} (${vulnerabilities.length} vulnerabilities)
${vulnerabilities.map(vuln => 
    `- ${vuln.title} (Likelihood: ${vuln.likelihood}, Impact: ${vuln.impact})`
).join('\n')}

`
).join('')}

`;
    }

    generateComplianceMappingMarkdown(complianceMapping) {
        return `
## Compliance Mapping

${Object.entries(complianceMapping).map(([framework, compliance]) => 
    `### ${framework} Compliance
- **Compliance Score:** ${compliance.complianceScore}%
- **Compliant Vulnerabilities:** ${compliance.compliantVulnerabilities}
- **Non-Compliant Vulnerabilities:** ${compliance.nonCompliantVulnerabilities}

${Object.keys(compliance.violationsByRequirement).length > 0 ? 
    `#### Violations by Requirement
${Object.entries(compliance.violationsByRequirement).map(([req, count]) => 
    `- **${req}:** ${count} violations`
).join('\n')}

` : ''}`
).join('')}

`;
    }

    generateSecurityPostureMarkdown(posture) {
        return `
## Security Posture Analysis

- **Average Risk Score:** ${posture.averageRisk}/10
- **Network Exposure Score:** ${posture.networkExposureScore}/10
- **Privilege Risk Score:** ${posture.privilegeRiskScore}/10
- **Security Maturity Index:** ${posture.maturityIndex}%
- **Controlled Vulnerabilities:** ${posture.controlledVulnerabilities}/${posture.totalVulnerabilities}

### Risk Distribution
${Object.entries(posture.riskDistribution).map(([severity, count]) => 
    `- **${severity}:** ${count} vulnerabilities`
).join('\n')}

`;
    }

    generateMathematicalAppendixMarkdown(data) {
        return `
## Mathematical Appendix

### Technical Debt Calculation
\`\`\`
TD = Σ(VI × TDF × EF × AC)
\`\`\`

Where:
- VI = Vulnerability Impact = (VC + VI + VA) / 3
- TDF = Time Decay Factor = 1 + (Days_Since_Disclosure / 365) × 0.1
- EF = Exploitability Factor = (AV + AC + AT) / 3
- AC = Asset Criticality (1.0-5.0)

### Remediation Effort Calculation
\`\`\`
FE = BE × CM × TE × A
\`\`\`

Where:
- FE = Final Effort (person-days)
- BE = Base Effort (based on CVSS score)
- CM = Complexity Multiplier (product of component multipliers)
- TE = Team Efficiency (0.7-1.3)
- A = Availability (0.8-1.0)

### Risk Matrix Calculation
\`\`\`
L = (ES + TF) / 2
\`\`\`

Where:
- L = Likelihood (0-1)
- ES = Exploitability Score = (AV + AC + AT + PR + UI) / 5
- TF = Temporal Factors = (E + AU + R) / 3

### Security Posture Calculation
\`\`\`
SMI = (Controlled_Vulns / Total_Vulns) × 100
\`\`\`

Where Controlled_Vulns = vulnerabilities where AC=H AND PR=H AND UI=A

`;
    }

    generateTextReport(data) {
        let text = `${data.metadata.reportTitle}\n`;
        text += `Assessment Date: ${data.metadata.assessmentDate}\n`;
        text += `Organisation: ${data.metadata.organisation}\n`;
        text += `Total Findings: ${data.metadata.totalFindings}\n`;
        text += `Generated: ${new Date(data.metadata.generatedAt).toLocaleString()}\n\n`;

        if (data.executiveSummary) {
            text += 'EXECUTIVE SUMMARY\n';
            text += '================\n';
            text += `Total Findings: ${data.executiveSummary.totalFindings}\n`;
            text += `Critical Findings: ${data.executiveSummary.criticalFindings}\n`;
            text += `Technical Debt: ${data.executiveSummary.technicalDebt.toFixed(2)}\n`;
            text += `Remediation Effort: ${data.executiveSummary.remediationEffort.toFixed(1)} person-days\n`;
            text += `Security Maturity: ${data.executiveSummary.securityMaturity}%\n`;
            text += `Average Risk: ${data.executiveSummary.averageRisk.toFixed(1)}/10\n\n`;

            text += 'KEY INSIGHTS:\n';
            data.executiveSummary.keyInsights.forEach((insight, index) => {
                text += `${index + 1}. ${insight}\n`;
            });
            text += '\n';

            text += 'TOP RECOMMENDATIONS:\n';
            data.executiveSummary.topRecommendations.forEach((rec, index) => {
                text += `${index + 1}. ${rec}\n`;
            });
            text += '\n';
        }

        if (data.technicalDebt) {
            text += 'TECHNICAL DEBT ANALYSIS\n';
            text += '======================\n';
            text += `Total Technical Debt: ${data.technicalDebt.totalDebt}\n`;
            text += `Average per Vulnerability: ${data.technicalDebt.averageDebtPerVuln}\n\n`;
        }

        if (data.remediationEffort) {
            text += 'REMEDIATION EFFORT ANALYSIS\n';
            text += '===========================\n';
            text += `Total Effort: ${data.remediationEffort.totalEffort} person-days\n`;
            text += `Average per Vulnerability: ${data.remediationEffort.averageEffortPerVuln} person-days\n\n`;
        }

        if (data.securityPosture) {
            text += 'SECURITY POSTURE ANALYSIS\n';
            text += '=========================\n';
            text += `Average Risk Score: ${data.securityPosture.averageRisk}/10\n`;
            text += `Security Maturity Index: ${data.securityPosture.maturityIndex}%\n`;
            text += `Controlled Vulnerabilities: ${data.securityPosture.controlledVulnerabilities}/${data.securityPosture.totalVulnerabilities}\n\n`;
        }

        text += 'MATHEMATICAL APPENDIX\n';
        text += '=====================\n\n';
        text += 'Technical Debt Calculation:\n';
        text += 'TD = Σ(VI × TDF × EF × AC)\n';
        text += 'Where:\n';
        text += '  VI = Vulnerability Impact = (VC + VI + VA) / 3\n';
        text += '  TDF = Time Decay Factor = 1 + (Days_Since_Disclosure / 365) × 0.1\n';
        text += '  EF = Exploitability Factor = (AV + AC + AT) / 3\n';
        text += '  AC = Asset Criticality (1.0-5.0)\n\n';

        text += 'Remediation Effort Calculation:\n';
        text += 'FE = BE × CM × TE × A\n';
        text += 'Where:\n';
        text += '  FE = Final Effort (person-days)\n';
        text += '  BE = Base Effort (based on CVSS score)\n';
        text += '  CM = Complexity Multiplier (product of component multipliers)\n';
        text += '  TE = Team Efficiency (0.7-1.3)\n';
        text += '  A = Availability (0.8-1.0)\n\n';

        text += 'Risk Matrix Calculation:\n';
        text += 'L = (ES + TF) / 2\n';
        text += 'Where:\n';
        text += '  L = Likelihood (0-1)\n';
        text += '  ES = Exploitability Score = (AV + AC + AT + PR + UI) / 5\n';
        text += '  TF = Temporal Factors = (E + AU + R) / 3\n\n';

        return text;
    }

    // Additional helper methods for HTML generation
    generateReportHeader(metadata) {
        return `
        <header class="report-header">
            <h1>${metadata.reportTitle}</h1>
            <div class="report-meta">
                <p><strong>Assessment Date:</strong> ${metadata.assessmentDate}</p>
                <p><strong>Organisation:</strong> ${metadata.organisation}</p>
                <p><strong>Assessor:</strong> ${metadata.assessor}</p>
                <p><strong>Total Findings:</strong> ${metadata.totalFindings}</p>
                <p><strong>Generated:</strong> ${new Date(metadata.generatedAt).toLocaleString()}</p>
            </div>
        </header>`;
    }

    generateRemediationEffortHTML(effort) {
        return `
        <section class="remediation-effort">
            <h2>Remediation Effort Analysis</h2>
            <div class="effort-metrics">
                <div class="metric-row">
                    <span class="metric-label">Total Effort:</span>
                    <span class="metric-value">${effort.totalEffort} person-days</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Average per Vulnerability:</span>
                    <span class="metric-value">${effort.averageEffortPerVuln} person-days</span>
                </div>
            </div>
            <div class="effort-breakdown">
                <h3>Effort by Complexity</h3>
                <div class="breakdown-chart">
                    ${Object.entries(effort.effortByComplexity).map(([complexity, amount]) => 
                        `<div class="breakdown-item">
                            <span class="complexity">${complexity}:</span>
                            <span class="amount">${amount.toFixed(1)} person-days</span>
                        </div>`
                    ).join('')}
                </div>
            </div>
            <div class="resource-requirements">
                <h3>Resource Requirements</h3>
                <div class="resource-grid">
                    <div class="resource-item">Person Days: ${effort.resourceRequirements.personDays}</div>
                    <div class="resource-item">Team Weeks: ${effort.resourceRequirements.teamWeeks}</div>
                    <div class="resource-item">Team Months: ${effort.resourceRequirements.teamMonths}</div>
                    <div class="resource-item">Recommended Team Size: ${effort.resourceRequirements.recommendedTeamSize}</div>
                </div>
            </div>
        </section>`;
    }

    generateRiskMatrixHTML(riskMatrix) {
        return `
        <section class="risk-matrix">
            <h2>Dynamic Risk Matrix</h2>
            <div class="risk-distribution">
                ${Object.entries(riskMatrix).map(([riskLevel, vulnerabilities]) => 
                    `<div class="risk-category">
                        <h3>${riskLevel} (${vulnerabilities.length} vulnerabilities)</h3>
                        <ul>
                            ${vulnerabilities.map(vuln => 
                                `<li>${vuln.title} (Likelihood: ${vuln.likelihood}, Impact: ${vuln.impact})</li>`
                            ).join('')}
                        </ul>
                    </div>`
                ).join('')}
            </div>
        </section>`;
    }

    generateComplianceMappingHTML(complianceMapping) {
        return `
        <section class="compliance-mapping">
            <h2>Compliance Mapping</h2>
            ${Object.entries(complianceMapping).map(([framework, compliance]) => 
                `<div class="compliance-framework">
                    <h3>${framework} Compliance</h3>
                    <div class="compliance-metrics">
                        <div class="metric-row">
                            <span class="metric-label">Compliance Score:</span>
                            <span class="metric-value ${compliance.complianceScore >= 70 ? 'good' : 'poor'}">${compliance.complianceScore}%</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-label">Compliant Vulnerabilities:</span>
                            <span class="metric-value">${compliance.compliantVulnerabilities}</span>
                        </div>
                        <div class="metric-row">
                            <span class="metric-label">Non-Compliant Vulnerabilities:</span>
                            <span class="metric-value">${compliance.nonCompliantVulnerabilities}</span>
                        </div>
                    </div>
                    ${Object.keys(compliance.violationsByRequirement).length > 0 ? `
                        <div class="violations">
                            <h4>Violations by Requirement</h4>
                            <ul>
                                ${Object.entries(compliance.violationsByRequirement).map(([req, count]) => 
                                    `<li>${req}: ${count} violations</li>`
                                ).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>`
            ).join('')}
        </section>`;
    }

    generateSecurityPostureHTML(posture) {
        return `
        <section class="security-posture">
            <h2>Security Posture Analysis</h2>
            <div class="posture-metrics">
                <div class="metric-row">
                    <span class="metric-label">Average Risk Score:</span>
                    <span class="metric-value">${posture.averageRisk}/10</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Network Exposure Score:</span>
                    <span class="metric-value">${posture.networkExposureScore}/10</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Privilege Risk Score:</span>
                    <span class="metric-value">${posture.privilegeRiskScore}/10</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Security Maturity Index:</span>
                    <span class="metric-value ${posture.maturityIndex >= 50 ? 'good' : 'poor'}">${posture.maturityIndex}%</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Controlled Vulnerabilities:</span>
                    <span class="metric-value">${posture.controlledVulnerabilities}/${posture.totalVulnerabilities}</span>
                </div>
            </div>
            <div class="risk-distribution">
                <h3>Risk Distribution</h3>
                <div class="distribution-chart">
                    ${Object.entries(posture.riskDistribution).map(([severity, count]) => 
                        `<div class="distribution-item">
                            <span class="severity">${severity}:</span>
                            <span class="count">${count} vulnerabilities</span>
                        </div>`
                    ).join('')}
                </div>
            </div>
        </section>`;
    }

    generateVulnerabilityClusteringHTML(clusters) {
        return `
        <section class="vulnerability-clustering">
            <h2>Vulnerability Clustering</h2>
            <div class="clusters">
                ${clusters.map((cluster, index) => 
                    `<div class="cluster">
                        <h3>Cluster ${index + 1}</h3>
                        <p><strong>Centroid Vector:</strong> ${cluster.centroid.AV}/${cluster.centroid.AC}/${cluster.centroid.PR}</p>
                        <p><strong>Vulnerabilities:</strong> ${cluster.vulnerabilities.length}</p>
                        <ul>
                            ${cluster.vulnerabilities.map(vuln => 
                                `<li>${vuln.title} (${vuln.CVSS})</li>`
                            ).join('')}
                        </ul>
                    </div>`
                ).join('')}
            </div>
        </section>`;
    }

    generateDetailedAnalysisHTML(analysis) {
        return `
        <section class="detailed-analysis">
            <h2>Detailed Analysis</h2>
            <div class="analysis-sections">
                <div class="analysis-section">
                    <h3>Vulnerability Distribution</h3>
                    <div class="distribution-chart">
                        ${Object.entries(analysis.vulnerabilityDistribution).map(([severity, count]) => 
                            `<div class="distribution-item">
                                <span class="severity">${severity}:</span>
                                <span class="count">${count}</span>
                            </div>`
                        ).join('')}
                    </div>
                </div>
                <div class="analysis-section">
                    <h3>Attack Vector Analysis</h3>
                    <div class="distribution-chart">
                        ${Object.entries(analysis.attackVectorAnalysis).map(([vector, count]) => 
                            `<div class="distribution-item">
                                <span class="vector">${vector}:</span>
                                <span class="count">${count}</span>
                            </div>`
                        ).join('')}
                    </div>
                </div>
            </div>
        </section>`;
    }

    generateRecommendationsHTML(recommendations) {
        return `
        <section class="recommendations">
            <h2>Recommendations</h2>
            <div class="recommendations-list">
                ${recommendations.map((rec, index) => 
                    `<div class="recommendation ${rec.priority.toLowerCase()}">
                        <h3>${index + 1}. ${rec.title}</h3>
                        <p class="category">Category: ${rec.category} | Priority: ${rec.priority}</p>
                        <p class="description">${rec.description}</p>
                        <p class="action"><strong>Action:</strong> ${rec.action}</p>
                    </div>`
                ).join('')}
            </div>
        </section>`;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CVSSReportGenerator;
} else if (typeof window !== 'undefined') {
    window.CVSSReportGenerator = CVSSReportGenerator;
}
