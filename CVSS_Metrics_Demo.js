/**
 * Campbell Murray - Sodium Cyber Ltd - 2025
 * CVSS Management Metrics Demonstration
 * 
 * This script demonstrates how to use CVSS vectors to generate
 * management metrics for technical debt, risk matrix, and compliance.
 */

// Import the CVSSMetricsCalculator class
const CVSSMetricsCalculator = require('./CVSS_Metrics_Implementation.js');

// Sample vulnerability data for demonstration
const sampleVulnerabilities = [
    {
        id: 'VULN-001',
        title: 'SQL Injection in Login Form',
        cvssScore: '8.8',
        vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/S:U/E:A/AU:Y/R:U',
        disclosureDate: '2024-01-15',
        category: 'Web Application',
        asset: 'Customer Portal'
    },
    {
        id: 'VULN-002',
        title: 'Buffer Overflow in Legacy Service',
        cvssScore: '7.5',
        vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/S:U/E:P/AU:N/R:U',
        disclosureDate: '2024-02-01',
        category: 'Infrastructure',
        asset: 'Legacy API'
    },
    {
        id: 'VULN-003',
        title: 'Cross-Site Scripting (XSS)',
        cvssScore: '6.1',
        vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:L/VI:L/VA:N/S:U/E:U/AU:N/R:U',
        disclosureDate: '2024-01-20',
        category: 'Web Application',
        asset: 'Admin Panel'
    },
    {
        id: 'VULN-004',
        title: 'Privilege Escalation via Service',
        cvssScore: '9.1',
        vector: 'CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/S:C/E:A/AU:Y/R:N',
        disclosureDate: '2024-01-10',
        category: 'Infrastructure',
        asset: 'Core System'
    },
    {
        id: 'VULN-005',
        title: 'Information Disclosure in Logs',
        cvssScore: '4.3',
        vector: 'CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:R/VC:L/VI:N/VA:N/S:U/E:U/AU:N/R:U',
        disclosureDate: '2024-02-05',
        category: 'Infrastructure',
        asset: 'Logging System'
    },
    {
        id: 'VULN-006',
        title: 'Denial of Service via Resource Exhaustion',
        cvssScore: '5.3',
        vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/S:U/E:U/AU:N/R:U',
        disclosureDate: '2024-01-25',
        category: 'Infrastructure',
        asset: 'Web Server'
    }
];

// Initialize the calculator
const calculator = new CVSSMetricsCalculator();

/**
 * Demonstrate technical debt calculation
 */
function demonstrateTechnicalDebt() {
    console.log('=== TECHNICAL DEBT CALCULATION ===\n');
    
    // Calculate technical debt with different asset criticality levels
    const criticalAssets = sampleVulnerabilities.filter(v => v.asset === 'Core System');
    const normalAssets = sampleVulnerabilities.filter(v => v.asset !== 'Core System');
    
    const criticalDebt = calculator.calculateTechnicalDebt(criticalAssets, 5.0);
    const normalDebt = calculator.calculateTechnicalDebt(normalAssets, 1.0);
    const totalDebt = calculator.calculateTechnicalDebt(sampleVulnerabilities, 2.0);
    
    console.log('Critical Asset Technical Debt:');
    console.log(`  Total Debt: ${criticalDebt.totalDebt}`);
    console.log(`  By Severity:`, criticalDebt.debtBySeverity);
    console.log(`  By Vector:`, criticalDebt.debtByVector);
    console.log(`  Trend: ${criticalDebt.debtTrend.trend}\n`);
    
    console.log('Normal Asset Technical Debt:');
    console.log(`  Total Debt: ${normalDebt.totalDebt}`);
    console.log(`  Average per Vulnerability: ${normalDebt.averageDebtPerVuln}\n`);
    
    console.log('Overall Technical Debt:');
    console.log(`  Total Debt: ${totalDebt.totalDebt}`);
    console.log(`  Average per Vulnerability: ${totalDebt.averageDebtPerVuln}\n`);
}

/**
 * Demonstrate remediation effort calculation
 */
function demonstrateRemediationEffort() {
    console.log('=== REMEDIATION EFFORT CALCULATION ===\n');
    
    const effort = calculator.calculateRemediationEffort(sampleVulnerabilities, 1.0);
    
    console.log('Remediation Effort Analysis:');
    console.log(`  Total Effort: ${effort.totalEffort} person-days`);
    console.log(`  Average per Vulnerability: ${effort.averageEffortPerVuln} person-days`);
    console.log(`  By Complexity:`, effort.effortByComplexity);
    console.log(`  By Attack Vector:`, effort.effortByVector);
    console.log('\nResource Requirements:');
    console.log(`  Person Days: ${effort.resourceRequirements.personDays}`);
    console.log(`  Team Weeks: ${effort.resourceRequirements.teamWeeks}`);
    console.log(`  Team Months: ${effort.resourceRequirements.teamMonths}`);
    console.log(`  Recommended Team Size: ${effort.resourceRequirements.recommendedTeamSize}\n`);
}

/**
 * Demonstrate risk matrix generation
 */
function demonstrateRiskMatrix() {
    console.log('=== RISK MATRIX GENERATION ===\n');
    
    const riskMatrix = calculator.generateRiskMatrix(sampleVulnerabilities);
    
    console.log('Risk Matrix Distribution:');
    Object.keys(riskMatrix).forEach(riskLevel => {
        const count = riskMatrix[riskLevel].length;
        if (count > 0) {
            console.log(`  ${riskLevel}: ${count} vulnerabilities`);
            riskMatrix[riskLevel].forEach(vuln => {
                console.log(`    - ${vuln.title} (Likelihood: ${vuln.likelihood}, Impact: ${vuln.impact})`);
            });
        }
    });
    console.log();
}

/**
 * Demonstrate compliance mapping
 */
function demonstrateComplianceMapping() {
    console.log('=== COMPLIANCE MAPPING ===\n');
    
    // Test different compliance frameworks
    const frameworks = ['PCI', 'SOX', 'HIPAA'];
    
    frameworks.forEach(framework => {
        console.log(`${framework} Compliance Analysis:`);
        const compliance = calculator.mapCompliance(sampleVulnerabilities, framework);
        
        console.log(`  Total Vulnerabilities: ${compliance.totalVulnerabilities}`);
        console.log(`  Compliant: ${compliance.compliantVulnerabilities}`);
        console.log(`  Non-Compliant: ${compliance.nonCompliantVulnerabilities}`);
        console.log(`  Compliance Score: ${compliance.complianceScore}%`);
        
        if (Object.keys(compliance.violationsByRequirement).length > 0) {
            console.log('  Violations by Requirement:');
            Object.keys(compliance.violationsByRequirement).forEach(req => {
                console.log(`    ${req}: ${compliance.violationsByRequirement[req]} violations`);
            });
        }
        
        if (compliance.recommendations.length > 0) {
            console.log('  Top Recommendations:');
            compliance.recommendations.slice(0, 3).forEach(rec => {
                console.log(`    ${rec.requirement} (${rec.priority}): ${rec.action}`);
            });
        }
        console.log();
    });
}

/**
 * Demonstrate security posture analysis
 */
function demonstrateSecurityPosture() {
    console.log('=== SECURITY POSTURE ANALYSIS ===\n');
    
    const posture = calculator.calculateSecurityPosture(sampleVulnerabilities);
    
    console.log('Security Posture Metrics:');
    console.log(`  Average Risk Score: ${posture.averageRisk}`);
    console.log(`  Network Exposure Score: ${posture.networkExposureScore}`);
    console.log(`  Privilege Risk Score: ${posture.privilegeRiskScore}`);
    console.log(`  Security Maturity Index: ${posture.maturityIndex}%`);
    console.log(`  Controlled Vulnerabilities: ${posture.controlledVulnerabilities}/${posture.totalVulnerabilities}`);
    
    console.log('\nRisk Distribution:');
    Object.keys(posture.riskDistribution).forEach(severity => {
        const count = posture.riskDistribution[severity];
        const percentage = Math.round((count / posture.totalVulnerabilities) * 100);
        console.log(`  ${severity}: ${count} vulnerabilities (${percentage}%)`);
    });
    console.log();
}

/**
 * Demonstrate vulnerability clustering
 */
function demonstrateVulnerabilityClustering() {
    console.log('=== VULNERABILITY CLUSTERING ===\n');
    
    const clusters = calculator.clusterVulnerabilities(sampleVulnerabilities, 0.7);
    
    console.log(`Found ${clusters.length} vulnerability clusters:`);
    clusters.forEach((cluster, index) => {
        console.log(`\nCluster ${index + 1}:`);
        console.log(`  Centroid Vector: ${cluster.centroid.AV}/${cluster.centroid.AC}/${cluster.centroid.PR}`);
        console.log(`  Vulnerabilities: ${cluster.vulnerabilities.length}`);
        cluster.vulnerabilities.forEach(vuln => {
            console.log(`    - ${vuln.title} (${vuln.cvssScore})`);
        });
    });
    console.log();
}

/**
 * Generate executive summary report
 */
function generateExecutiveSummary() {
    console.log('=== EXECUTIVE SUMMARY REPORT ===\n');
    
    const technicalDebt = calculator.calculateTechnicalDebt(sampleVulnerabilities, 2.0);
    const remediationEffort = calculator.calculateRemediationEffort(sampleVulnerabilities, 1.0);
    const securityPosture = calculator.calculateSecurityPosture(sampleVulnerabilities);
    const pciCompliance = calculator.mapCompliance(sampleVulnerabilities, 'PCI');
    
    console.log('EXECUTIVE DASHBOARD METRICS');
    console.log('============================');
    console.log(`Total Technical Debt: ${technicalDebt.totalDebt} (debt units)`);
    console.log(`Remediation Backlog: ${remediationEffort.totalEffort} person-days`);
    console.log(`Security Maturity: ${securityPosture.maturityIndex}%`);
    console.log(`PCI Compliance: ${pciCompliance.complianceScore}%`);
    console.log(`Average Risk Score: ${securityPosture.averageRisk}/10`);
    
    console.log('\nKEY INSIGHTS');
    console.log('============');
    console.log(`• ${technicalDebt.debtBySeverity.Critical || 0} critical vulnerabilities contributing to technical debt`);
    console.log(`• ${remediationEffort.effortByComplexity.High || 0} high-complexity vulnerabilities requiring significant effort`);
    console.log(`• ${securityPosture.controlledVulnerabilities} vulnerabilities are well-controlled (hard to exploit)`);
    console.log(`• ${pciCompliance.nonCompliantVulnerabilities} vulnerabilities violate PCI requirements`);
    
    console.log('\nRECOMMENDATIONS');
    console.log('===============');
    console.log('1. Prioritise remediation of critical vulnerabilities to reduce technical debt');
    console.log('2. Allocate additional resources for high-complexity remediation efforts');
    console.log('3. Focus on network-accessible vulnerabilities to reduce attack surface');
    console.log('4. Address PCI compliance violations to meet regulatory requirements');
    console.log('5. Implement additional controls for vulnerabilities requiring low privileges');
}

/**
 * Run all demonstrations
 */
function runAllDemonstrations() {
    console.log('CVSS MANAGEMENT METRICS DEMONSTRATION');
    console.log('=====================================\n');
    
    demonstrateTechnicalDebt();
    demonstrateRemediationEffort();
    demonstrateRiskMatrix();
    demonstrateComplianceMapping();
    demonstrateSecurityPosture();
    demonstrateVulnerabilityClustering();
    generateExecutiveSummary();
}

// Run demonstrations if this script is executed directly
if (typeof window !== 'undefined' && window.location) {
    // Browser environment
    document.addEventListener('DOMContentLoaded', () => {
        runAllDemonstrations();
    });
} else if (typeof require !== 'undefined') {
    // Node.js environment
    runAllDemonstrations();
}
