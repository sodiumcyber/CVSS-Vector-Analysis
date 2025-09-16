/**
 * CVSS Management Report Generator Demo
 * 
 * Demonstrates how to generate comprehensive management reports
 * with CVSS-based calculations for appendices and management summaries.
 */

// Import required modules
const CVSSMetricsCalculator = require('./CVSS_Metrics_Implementation.js');
const CVSSReportGenerator = require('./CVSS_Report_Generator.js');
const fs = require('fs');
const path = require('path');

// Sample vulnerability data (same as before)
const sampleVulnerabilities = [
    {
        id: 'VULN-001',
        title: 'SQL Injection in Login Form',
        CVSS: '8.8',
        CVSSVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/S:U/E:A/AU:Y/R:U',
        disclosureDate: '2024-01-15',
        category: 'Web Application',
        AffectedComponents: 'Customer Portal, Authentication Service'
    },
    {
        id: 'VULN-002',
        title: 'Buffer Overflow in Legacy Service',
        CVSS: '7.5',
        CVSSVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/S:U/E:P/AU:N/R:U',
        disclosureDate: '2024-02-01',
        category: 'Infrastructure',
        AffectedComponents: 'Legacy API, Core Services'
    },
    {
        id: 'VULN-003',
        title: 'Cross-Site Scripting (XSS)',
        CVSS: '6.1',
        CVSSVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:L/VI:L/VA:N/S:U/E:U/AU:N/R:U',
        disclosureDate: '2024-01-20',
        category: 'Web Application',
        AffectedComponents: 'Admin Panel, User Interface'
    },
    {
        id: 'VULN-004',
        title: 'Privilege Escalation via Service',
        CVSS: '9.1',
        CVSSVector: 'CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/S:C/E:A/AU:Y/R:N',
        disclosureDate: '2024-01-10',
        category: 'Infrastructure',
        AffectedComponents: 'Core System, Privilege Management'
    },
    {
        id: 'VULN-005',
        title: 'Information Disclosure in Logs',
        CVSS: '4.3',
        CVSSVector: 'CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:R/VC:L/VI:N/VA:N/S:U/E:U/AU:N/R:U',
        disclosureDate: '2024-02-05',
        category: 'Infrastructure',
        AffectedComponents: 'Logging System, Monitoring'
    },
    {
        id: 'VULN-006',
        title: 'Denial of Service via Resource Exhaustion',
        CVSS: '5.3',
        CVSSVector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/S:U/E:U/AU:N/R:U',
        disclosureDate: '2024-01-25',
        category: 'Infrastructure',
        AffectedComponents: 'Web Server, Load Balancer'
    }
];

/**
 * Demonstrate report generation
 */
function demonstrateReportGeneration() {

    
    // Initialize report generator
    const reportGenerator = new CVSSReportGenerator();
    
    // Set report metadata
    reportGenerator.templateData = {
        reportTitle: 'Security Assessment Management Report',
        assessmentDate: '2024-02-15',
        organisation: 'Acme Corporation',
        assessor: 'Security Assessment Team',
        reportVersion: '1.0'
    };
    
    // Generate comprehensive report
    console.log('Generating comprehensive management report...');
    const reportData = reportGenerator.generateManagementReport(sampleVulnerabilities, {
        includeTechnicalDebt: true,
        includeRemediationEffort: true,
        includeRiskMatrix: true,
        includeComplianceMapping: true,
        includeSecurityPosture: true,
        includeVulnerabilityClustering: true,
        includeExecutiveSummary: true,
        assetCriticality: 2.0,
        teamEfficiency: 1.0,
        complianceFrameworks: ['PCI', 'SOX', 'HIPAA']
    });
    
    console.log('✅ Report generated successfully!\n');
    
    
    // Display key insights
    console.log('KEY INSIGHTS:');
    reportData.executiveSummary.keyInsights.forEach((insight, index) => {
        console.log(`${index + 1}. ${insight}`);
    });
    console.log();
    
    // Display top recommendations
    console.log('TOP RECOMMENDATIONS:');
    reportData.executiveSummary.topRecommendations.forEach((rec, index) => {
        console.log(`${index + 1}. ${rec}`);
    });
    console.log();
    
    return reportData;
}

/**
 * Different output formats
 */
function demonstrateOutputFormats(reportData) {
    console.log('OUTPUT FORMAT DEMONSTRATION');
    console.log('===========================\n');
    
    const reportGenerator = new CVSSReportGenerator();
    reportGenerator.reportData = reportData;
    
    // Generate HTML report
    console.log('Generating HTML report...');
    const htmlReport = reportGenerator.generateFormattedReport(reportData, 'html');
    
    // Generate Markdown report
    console.log('Generating Markdown report...');
    const markdownReport = reportGenerator.generateFormattedReport(reportData, 'markdown');
    
    // Generate Text report
    console.log('Generating Text report...');
    const textReport = reportGenerator.generateFormattedReport(reportData, 'text');
    
    return { htmlReport, markdownReport, textReport };
}

/**
 * Save reports to files
 */
function saveReportsToFiles(reports) {
    console.log('\nSAVING REPORTS TO FILES');
    console.log('=======================\n');
    
    const outputDir = path.join(__dirname, 'generated_reports');
    
    // Create output directory if it doesn't exist
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
        console.log(`Created output directory: ${outputDir}`);
    }
    
    // Save HTML report
    const htmlPath = path.join(outputDir, 'management_report.html');
    fs.writeFileSync(htmlPath, reports.htmlReport);
    
    // Save Markdown report
    const markdownPath = path.join(outputDir, 'management_report.md');
    fs.writeFileSync(markdownPath, reports.markdownReport);
    
    // Save Text report
    const textPath = path.join(outputDir, 'management_report.txt');
    fs.writeFileSync(textPath, reports.textReport);

}

/**
 * Demonstrate report customization
 */
function demonstrateReportCustomization() {
    console.log('\nREPORT DEMONSTRATION');
    console.log('==================================\n');
    
    const reportGenerator = new CVSSReportGenerator();
    
    // Customize report metadata
    reportGenerator.templateData = {
        reportTitle: 'Quarterly Security Assessment Report',
        assessmentDate: '2024-Q1',
        organisation: 'TechCorp Industries',
        assessor: 'Internal Security Team',
        reportVersion: '2.1'
    };
    
    // Generate focused report (only specific sections)
    console.log('Generating focused report (Technical Debt + Remediation Effort only)...');
    const focusedReport = reportGenerator.generateManagementReport(sampleVulnerabilities, {
        includeTechnicalDebt: true,
        includeRemediationEffort: true,
        includeRiskMatrix: false,
        includeComplianceMapping: false,
        includeSecurityPosture: false,
        includeVulnerabilityClustering: false,
        includeExecutiveSummary: true,
        assetCriticality: 3.0, // Higher criticality
        teamEfficiency: 0.8,   // Lower efficiency
        complianceFrameworks: ['PCI'] // Only PCI
    });
    
    
    // Generate executive-only report
    console.log('Generating executive-only report...');
    const executiveReport = reportGenerator.generateManagementReport(sampleVulnerabilities, {
        includeTechnicalDebt: false,
        includeRemediationEffort: false,
        includeRiskMatrix: false,
        includeComplianceMapping: false,
        includeSecurityPosture: true,
        includeVulnerabilityClustering: false,
        includeExecutiveSummary: true,
        assetCriticality: 2.0,
        teamEfficiency: 1.0,
        complianceFrameworks: []
    });
    
}

/**
 * Demonstrate integration with existing  data
 */
function demonstratePiperineIntegration() {

    // Simulate findings data structure
    const piperineFindings = sampleVulnerabilities.map(vuln => ({
        id: vuln.id,
        title: vuln.title,
        CVSS: vuln.CVSS,
        CVSSVector: vuln.CVSSVector,
        disclosureDate: vuln.disclosureDate,
        category: vuln.category,
        AffectedComponents: vuln.AffectedComponents,
        severity: vuln.CVSS >= 9.0 ? 'Critical' : vuln.CVSS >= 7.0 ? 'High' : vuln.CVSS >= 4.0 ? 'Medium' : 'Low',
        status: 'Open',
        phase: 'Assessment',
        description: `Detailed description for ${vuln.title}`,
        recommendation: `Remediation recommendation for ${vuln.title}`
    }));
    
    console.log(`Found ${piperineFindings.length} findings from current report`);
    console.log();
    
    // Generate management report from data
    const reportGenerator = new CVSSReportGenerator();
    const reportData = reportGenerator.generateManagementReport(piperineFindings, {
        includeTechnicalDebt: true,
        includeRemediationEffort: true,
        includeRiskMatrix: true,
        includeComplianceMapping: true,
        includeSecurityPosture: true,
        includeVulnerabilityClustering: true,
        includeExecutiveSummary: true,
        assetCriticality: 2.0,
        teamEfficiency: 1.0,
        complianceFrameworks: ['PCI', 'SOX', 'HIPAA']
    });
    }

/**
 * Run all
 */
function runAllDemonstrations() {
    try {
        // Generate main report
        const reportData = demonstrateReportGeneration();
        
        // Demonstrate output formats
        const reports = demonstrateOutputFormats(reportData);
        
        // Save reports to files
        saveReportsToFiles(reports);
        
        // Demonstrate customization
        demonstrateReportCustomization();
        
        // Demonstrate Piperine integration
        demonstratePiperineIntegration();
        
        console.log('\nALL ELEMENTS GENERATED SUCCESSFULLY!');
        
    } catch (error) {
        console.error('Error during generation:', error.message);
        console.error(error.stack);
    }
}

// Run if this script is executed directly
if (require.main === module) {
    runAllDemonstrations();
}
