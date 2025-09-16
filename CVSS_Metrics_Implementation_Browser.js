/**
 * CVSS-Based Management Metrics Implementation (Browser Version)
 * 
 * This module provides practical implementations of CVSS-based management metrics
 * for technical debt, risk matrix, remediation effort, and compliance mapping.
 * This version is optimized for browser execution.
 */

class CVSSMetricsCalculator {
    constructor() {
        // CVSS 4.0 component weights
        this.weights = {
            AV: { N: 0.85, A: 0.6, L: 0.55, P: 0.2 },
            AC: { L: 0.77, H: 0.44 },
            AT: { N: 0.85, P: 0.62 },
            PR: { N: 0.85, L: 0.62, H: 0.27 },
            UI: { N: 0.85, P: 0.62, A: 0.45 },
            VC: { H: 0.56, L: 0.22, N: 0 },
            VI: { H: 0.56, L: 0.22, N: 0 },
            VA: { H: 0.56, L: 0.22, N: 0 },
            S: { N: 1.0, L: 0.9, M: 1.0, H: 1.1 },
            E: { U: 1.0, P: 1.0, A: 1.0, X: 1.0 },
            AU: { N: 1.0, Y: 1.0, X: 1.0 },
            R: { N: 1.1, U: 1.05, A: 0.95, X: 1.0 }
        };
        
        // Remediation effort multipliers
        this.effortMultipliers = {
            AV: { P: 0.5, L: 0.8, A: 1.2, N: 1.5 },
            AC: { H: 0.7, L: 1.3 },
            PR: { H: 0.6, L: 1.0, N: 1.4 },
            UI: { A: 0.8, P: 1.0, N: 1.2 },
            S: { U: 1.0, C: 1.5 }
        };
    }

    /**
     * Parse CVSS vector string into component object
     * @param {string} vector - CVSS vector string (e.g., "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")
     * @returns {Object} Parsed CVSS components
     */
    parseCVSSVector(vector) {
        const components = {};
        
        if (!vector || typeof vector !== 'string') {
            // Return default values if no vector provided
            return {
                AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N',
                VC: 'N', VI: 'N', VA: 'N', S: 'U', E: 'X', AU: 'X', R: 'X'
            };
        }
        
        const parts = vector.split('/');
        
        parts.forEach(part => {
            const [metric, value] = part.split(':');
            if (metric && value) {
                components[metric] = value;
            }
        });
        
        // Handle CVSS 3.x format by mapping to CVSS 4.0 format
        if (components.C && !components.VC) {
            components.VC = components.C;
        }
        if (components.I && !components.VI) {
            components.VI = components.I;
        }
        if (components.A && !components.VA) {
            components.VA = components.A;
        }
        
        // Ensure required components have default values
        return {
            AV: components.AV || 'N',
            AC: components.AC || 'L',
            AT: components.AT || 'N',
            PR: components.PR || 'N',
            UI: components.UI || 'N',
            S: components.S || 'U',
            VC: components.VC || 'N',
            VI: components.VI || 'N',
            VA: components.VA || 'N',
            E: components.E || 'X',
            AU: components.AU || 'X',
            R: components.R || 'X'
        };
    }

    /**
     * Calculate technical debt for a set of vulnerabilities
     * @param {Array} vulnerabilities - Array of vulnerability objects
     * @param {number} assetCriticality - Asset criticality multiplier (1.0-5.0)
     * @returns {Object} Technical debt metrics
     */
    calculateTechnicalDebt(vulnerabilities, assetCriticality = 1.0) {
        let totalDebt = 0;
        let debtBySeverity = { Low: 0, Medium: 0, High: 0, Critical: 0 };
        let debtByVector = {};
        
        vulnerabilities.forEach(vuln => {
            const cvss = this.parseCVSSVector(vuln.vector);
            const daysSinceDisclosure = this.getDaysSinceDisclosure(vuln.disclosureDate);
            
            // Calculate impact score (CIA average)
            const impact = (this.weights.VC[cvss.VC] + this.weights.VI[cvss.VI] + this.weights.VA[cvss.VA]) / 3;
            
            // Time decay factor (increases over time)
            const timeDecay = 1 + (daysSinceDisclosure / 365) * 0.1;
            
            // Exploitability factor
            const exploitability = (this.weights.AV[cvss.AV] + this.weights.AC[cvss.AC] + this.weights.AT[cvss.AT]) / 3;
            
            // Calculate debt for this vulnerability
            const vulnerabilityDebt = impact * timeDecay * exploitability * assetCriticality;
            totalDebt += vulnerabilityDebt;
            
            // Categorise by severity
            const severity = this.getSeverityFromScore(vuln.cvssScore);
            debtBySeverity[severity] += vulnerabilityDebt;
            
            // Track by attack vector
            const vector = cvss.AV;
            debtByVector[vector] = (debtByVector[vector] || 0) + vulnerabilityDebt;
        });
        
        return {
            totalDebt: Math.round(totalDebt * 100) / 100,
            debtBySeverity,
            debtByVector,
            averageDebtPerVuln: Math.round((totalDebt / vulnerabilities.length) * 100) / 100,
            debtTrend: this.calculateDebtTrend(vulnerabilities)
        };
    }

    /**
     * Calculate remediation effort for vulnerabilities
     * @param {Array} vulnerabilities - Array of vulnerability objects
     * @param {number} teamEfficiency - Team efficiency multiplier (0.7-1.3)
     * @returns {Object} Remediation effort metrics
     */
    calculateRemediationEffort(vulnerabilities, teamEfficiency = 1.0) {
        let totalEffort = 0;
        let effortByComplexity = { Low: 0, Medium: 0, High: 0 };
        let effortByVector = {};
        
        vulnerabilities.forEach(vuln => {
            const cvss = this.parseCVSSVector(vuln.vector);
            
            // Base effort based on CVSS score
            let baseEffort = this.getBaseEffort(vuln.cvssScore);
            
            // Apply complexity multipliers
            let complexityMultiplier = 1.0;
            Object.keys(this.effortMultipliers).forEach(metric => {
                if (cvss[metric] && this.effortMultipliers[metric][cvss[metric]]) {
                    complexityMultiplier *= this.effortMultipliers[metric][cvss[metric]];
                }
            });
            
            // Calculate final effort
            const effort = baseEffort * complexityMultiplier * teamEfficiency;
            totalEffort += effort;
            
            // Categorise by complexity
            const complexity = this.getComplexityLevel(complexityMultiplier);
            effortByComplexity[complexity] += effort;
            
            // Track by attack vector
            const vector = cvss.AV;
            effortByVector[vector] = (effortByVector[vector] || 0) + effort;
        });
        
        return {
            totalEffort: Math.round(totalEffort * 10) / 10,
            effortByComplexity,
            effortByVector,
            averageEffortPerVuln: Math.round((totalEffort / vulnerabilities.length) * 10) / 10,
            resourceRequirements: this.calculateResourceRequirements(totalEffort)
        };
    }

    /**
     * Generate risk matrix for vulnerabilities
     * @param {Array} vulnerabilities - Array of vulnerability objects
     * @returns {Object} Risk matrix with likelihood and impact scores
     */
    generateRiskMatrix(vulnerabilities) {
        const riskMatrix = {
            'Very High': [],
            'High': [],
            'Medium': [],
            'Low': []
        };

        vulnerabilities.forEach(vuln => {
            const cvss = this.parseCVSSVector(vuln.vector);
            
            // Calculate likelihood based on exploitability and temporal factors
            const exploitability = (this.weights.AV[cvss.AV] + this.weights.AC[cvss.AC] + 
                                  this.weights.AT[cvss.AT] + this.weights.PR[cvss.PR] + 
                                  this.weights.UI[cvss.UI]) / 5;
            
            // Temporal factors (simplified - in real implementation, use E, AU, R)
            const temporal = 0.8; // Default temporal score
            const likelihood = (exploitability + temporal) / 2;
            
            // Impact based on CVSS score
            const impact = Math.min(5, Math.max(1, Math.ceil(parseFloat(vuln.cvssScore) / 2)));
            
            // Determine risk level
            let riskLevel = 'Low';
            if (likelihood >= 0.8 && impact >= 4) riskLevel = 'Very High';
            else if (likelihood >= 0.6 && impact >= 3) riskLevel = 'High';
            else if (likelihood >= 0.4 && impact >= 2) riskLevel = 'Medium';
            
            riskMatrix[riskLevel].push({
                id: vuln.id,
                title: vuln.title,
                likelihood: Math.round(likelihood * 100) / 100,
                impact: impact,
                cvss: parseFloat(vuln.cvssScore)
            });
        });

        return riskMatrix;
    }

    /**
     * Calculate security posture metrics
     * @param {Array} vulnerabilities - Array of vulnerability objects
     * @returns {Object} Security posture analysis
     */
    calculateSecurityPosture(vulnerabilities) {
        let totalRisk = 0;
        let networkExposure = 0;
        let privilegeRisk = 0;
        let controlledVulnerabilities = 0;
        
        vulnerabilities.forEach(vuln => {
            const cvss = this.parseCVSSVector(vuln.vector);
            const score = parseFloat(vuln.cvssScore) || 0;
            
            totalRisk += score;
            
            // Network exposure (higher for network-accessible vulnerabilities)
            const networkFactor = this.weights.AV[cvss.AV];
            networkExposure += score * networkFactor;
            
            // Privilege escalation risk
            const privilegeFactor = this.weights.PR[cvss.PR];
            privilegeRisk += score * privilegeFactor;
            
            // Controlled vulnerabilities (harder to exploit)
            if (cvss.AC === 'H' && cvss.PR === 'H' && cvss.UI === 'A') {
                controlledVulnerabilities++;
            }
        });
        
        const averageRisk = totalRisk / vulnerabilities.length;
        const networkExposureScore = networkExposure / vulnerabilities.length;
        const privilegeRiskScore = privilegeRisk / vulnerabilities.length;
        const maturityIndex = (controlledVulnerabilities / vulnerabilities.length) * 100;
        
        return {
            averageRisk: Math.round(averageRisk * 10) / 10,
            networkExposureScore: Math.round(networkExposureScore * 10) / 10,
            privilegeRiskScore: Math.round(privilegeRiskScore * 10) / 10,
            maturityIndex: Math.round(maturityIndex * 10) / 10,
            controlledVulnerabilities,
            totalVulnerabilities: vulnerabilities.length,
            riskDistribution: this.calculateRiskDistribution(vulnerabilities)
        };
    }

    /**
     * Cluster vulnerabilities by CVSS vector similarity
     * @param {Array} vulnerabilities - Array of vulnerability objects
     * @param {number} threshold - Similarity threshold (0-1)
     * @returns {Array} Array of vulnerability clusters
     */
    clusterVulnerabilities(vulnerabilities, threshold = 0.7) {
        const clusters = [];
        const processed = new Set();
        
        vulnerabilities.forEach((vuln, index) => {
            if (processed.has(index)) return;
            
            const cluster = {
                centroid: this.parseCVSSVector(vuln.vector),
                vulnerabilities: [vuln]
            };
            
            processed.add(index);
            
            // Find similar vulnerabilities
            vulnerabilities.forEach((otherVuln, otherIndex) => {
                if (processed.has(otherIndex)) return;
                
                const similarity = this.calculateSimilarity(vuln.vector, otherVuln.vector);
                if (similarity >= threshold) {
                    cluster.vulnerabilities.push(otherVuln);
                    processed.add(otherIndex);
                }
            });
            
            clusters.push(cluster);
        });
        
        return clusters;
    }

    /**
     * Calculate similarity between two CVSS vectors
     * @param {string} vector1 - First CVSS vector
     * @param {string} vector2 - Second CVSS vector
     * @returns {number} Similarity score (0-1)
     */
    calculateSimilarity(vector1, vector2) {
        const components1 = this.parseCVSSVector(vector1);
        const components2 = this.parseCVSSVector(vector2);
        
        const importantComponents = ['AV', 'AC', 'PR', 'UI'];
        let matches = 0;
        
        importantComponents.forEach(comp => {
            if (components1[comp] === components2[comp]) {
                matches++;
            }
        });
        
        return matches / importantComponents.length;
    }

    /**
     * Map compliance requirements to vulnerabilities
     * @param {Array} vulnerabilities - Array of vulnerability objects
     * @param {string} framework - Compliance framework (PCI, SOX, HIPAA)
     * @returns {Object} Compliance mapping results
     */
    mapCompliance(vulnerabilities, framework) {
        const complianceRules = this.getComplianceRules(framework);
        let compliantCount = 0;
        const violationsByRequirement = {};
        const recommendations = [];
        
        vulnerabilities.forEach(vuln => {
            const cvss = this.parseCVSSVector(vuln.vector);
            const score = parseFloat(vuln.cvssScore) || 0;
            
            let isCompliant = true;
            
            complianceRules.forEach(rule => {
                if (this.evaluateComplianceRule(cvss, score, rule)) {
                    if (!violationsByRequirement[rule.requirement]) {
                        violationsByRequirement[rule.requirement] = 0;
                    }
                    violationsByRequirement[rule.requirement]++;
                    isCompliant = false;
                }
            });
            
            if (isCompliant) {
                compliantCount++;
            }
        });
        
        // Generate recommendations
        Object.keys(violationsByRequirement).forEach(requirement => {
            const rule = complianceRules.find(r => r.requirement === requirement);
            if (rule) {
                recommendations.push({
                    requirement: rule.requirement,
                    priority: rule.priority,
                    action: rule.action
                });
            }
        });
        
        return {
            totalVulnerabilities: vulnerabilities.length,
            compliantVulnerabilities: compliantCount,
            nonCompliantVulnerabilities: vulnerabilities.length - compliantCount,
            complianceScore: Math.round((compliantCount / vulnerabilities.length) * 100),
            violationsByRequirement,
            recommendations: recommendations.sort((a, b) => {
                const priorityOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
                return priorityOrder[b.priority] - priorityOrder[a.priority];
            })
        };
    }

    // Helper methods
    getDaysSinceDisclosure(disclosureDate) {
        const now = new Date();
        const disclosure = new Date(disclosureDate);
        return Math.floor((now - disclosure) / (1000 * 60 * 60 * 24));
    }

    getSeverityFromScore(score) {
        const numericScore = parseFloat(score);
        if (numericScore >= 9.0) return 'Critical';
        if (numericScore >= 7.0) return 'High';
        if (numericScore >= 4.0) return 'Medium';
        return 'Low';
    }

    getBaseEffort(score) {
        const numericScore = parseFloat(score);
        if (numericScore >= 9.0) return 15; // High effort for critical
        if (numericScore >= 7.0) return 8;  // Medium effort for high
        if (numericScore >= 4.0) return 4;  // Low effort for medium
        return 2; // Very low effort for low
    }

    getComplexityLevel(multiplier) {
        if (multiplier <= 0.7) return 'Low';
        if (multiplier <= 1.2) return 'Medium';
        return 'High';
    }

    calculateDebtTrend(vulnerabilities) {
        // Simplified trend calculation
        return { trend: 'stable', change: 0 };
    }

    calculateResourceRequirements(totalEffort) {
        return {
            personDays: Math.ceil(totalEffort),
            teamWeeks: Math.ceil(totalEffort / 5),
            teamMonths: Math.ceil(totalEffort / 20),
            recommendedTeamSize: Math.max(1, Math.ceil(totalEffort / 30))
        };
    }

    calculateRiskDistribution(vulnerabilities) {
        const distribution = { Low: 0, Medium: 0, High: 0, Critical: 0 };
        
        vulnerabilities.forEach(vuln => {
            const severity = this.getSeverityFromScore(vuln.cvssScore);
            distribution[severity]++;
        });
        
        return distribution;
    }

    getComplianceRules(framework) {
        const rules = {
            'PCI': [
                { requirement: 'Requirement 6.1', priority: 'Medium', action: 'Implement secure coding practices and regular security testing' },
                { requirement: 'Requirement 6.2', priority: 'Medium', action: 'Apply security patches and updates promptly' },
                { requirement: 'Requirement 11.2', priority: 'Medium', action: 'Conduct regular vulnerability scans and penetration testing' }
            ],
            'SOX': [
                { requirement: 'Financial Data Integrity', priority: 'High', action: 'Implement data integrity controls and monitoring' },
                { requirement: 'System Availability', priority: 'Medium', action: 'Implement high availability and disaster recovery measures' },
                { requirement: 'Access Controls', priority: 'High', action: 'Strengthen authentication and authorization mechanisms' }
            ],
            'HIPAA': [
                { requirement: 'Data Confidentiality', priority: 'Medium', action: 'Implement encryption and access controls for protected health information' },
                { requirement: 'Data Integrity', priority: 'Medium', action: 'Implement data integrity controls and audit logging' },
                { requirement: 'System Availability', priority: 'Medium', action: 'Implement high availability and disaster recovery measures' }
            ],
            'SOC2': [
                { requirement: 'CC6.1', priority: 'High', action: 'Implement logical and physical access controls' },
                { requirement: 'CC6.2', priority: 'High', action: 'Establish identity verification procedures prior to credential issuance' },
                { requirement: 'CC6.3', priority: 'High', action: 'Implement identity and access management controls' },
                { requirement: 'CC6.4', priority: 'High', action: 'Restrict access to information assets based on business need' },
                { requirement: 'CC6.5', priority: 'High', action: 'Restrict access to information assets based on business need' },
                { requirement: 'CC6.6', priority: 'High', action: 'Restrict access to information assets based on business need' },
                { requirement: 'CC6.7', priority: 'High', action: 'Restrict access to information assets based on business need' },
                { requirement: 'CC7.1', priority: 'Medium', action: 'Implement system operations controls' },
                { requirement: 'CC7.2', priority: 'Medium', action: 'Implement system operations controls' },
                { requirement: 'CC7.3', priority: 'Medium', action: 'Implement system operations controls' },
                { requirement: 'CC7.4', priority: 'Medium', action: 'Implement system operations controls' },
                { requirement: 'CC7.5', priority: 'Medium', action: 'Implement system operations controls' }
            ],
            'GDPR': [
                { requirement: 'Article 32 - Security of Processing', priority: 'High', action: 'Implement appropriate technical and organizational measures to ensure security of processing' },
                { requirement: 'Article 25 - Data Protection by Design', priority: 'High', action: 'Implement data protection by design and by default principles' },
                { requirement: 'Article 33 - Breach Notification', priority: 'High', action: 'Implement breach notification procedures and monitoring' },
                { requirement: 'Article 35 - Data Protection Impact Assessment', priority: 'Medium', action: 'Conduct data protection impact assessments for high-risk processing' },
                { requirement: 'Article 5 - Lawfulness of Processing', priority: 'Medium', action: 'Ensure lawful basis for processing personal data' }
            ],
            'NIST': [
                { requirement: 'PR.AC-1', priority: 'High', action: 'Implement identities and access management controls' },
                { requirement: 'PR.AC-3', priority: 'High', action: 'Implement remote access management controls' },
                { requirement: 'PR.AC-4', priority: 'High', action: 'Implement access permissions and authorizations' },
                { requirement: 'PR.AC-5', priority: 'High', action: 'Implement network integrity controls' },
                { requirement: 'PR.AC-6', priority: 'High', action: 'Implement least privilege access controls' },
                { requirement: 'PR.AC-7', priority: 'High', action: 'Implement user access management controls' },
                { requirement: 'PR.DS-1', priority: 'High', action: 'Implement data-at-rest protection' },
                { requirement: 'PR.DS-2', priority: 'High', action: 'Implement data-in-transit protection' },
                { requirement: 'PR.DS-3', priority: 'High', action: 'Implement data-in-use protection' },
                { requirement: 'PR.DS-4', priority: 'Medium', action: 'Ensure adequate capacity for availability' },
                { requirement: 'PR.DS-5', priority: 'Medium', action: 'Implement data loss prevention controls' },
                { requirement: 'PR.IP-1', priority: 'Medium', action: 'Implement baseline configurations' },
                { requirement: 'PR.IP-3', priority: 'Medium', action: 'Implement configuration change control' },
                { requirement: 'PR.MA-1', priority: 'Medium', action: 'Implement maintenance controls' },
                { requirement: 'PR.PT-1', priority: 'High', action: 'Implement protective technology controls' }
            ],
            'OWASP': [
                { requirement: 'A01:2021 - Broken Access Control', priority: 'High', action: 'Implement proper access controls and enforce the principle of least privilege' },
                { requirement: 'A02:2021 - Cryptographic Failures', priority: 'High', action: 'Implement proper encryption for data at rest and in transit' },
                { requirement: 'A03:2021 - Injection', priority: 'High', action: 'Use parameterized queries and input validation to prevent injection attacks' },
                { requirement: 'A04:2021 - Insecure Design', priority: 'Medium', action: 'Implement secure design principles and threat modeling' },
                { requirement: 'A05:2021 - Security Misconfiguration', priority: 'Medium', action: 'Implement secure configuration management and regular security reviews' },
                { requirement: 'A06:2021 - Vulnerable Components', priority: 'Medium', action: 'Implement component inventory and vulnerability management processes' },
                { requirement: 'A07:2021 - Authentication Failures', priority: 'High', action: 'Implement strong authentication mechanisms and session management' },
                { requirement: 'A08:2021 - Software and Data Integrity', priority: 'Medium', action: 'Implement integrity controls and secure update mechanisms' },
                { requirement: 'A09:2021 - Logging and Monitoring', priority: 'Medium', action: 'Implement comprehensive logging and monitoring capabilities' },
                { requirement: 'A10:2021 - Server-Side Request Forgery', priority: 'Medium', action: 'Implement proper input validation and network segmentation' }
            ],
            'ISO27001': [
                { requirement: 'A.5.1.1', priority: 'High', action: 'Implement information security policies' },
                { requirement: 'A.6.1.1', priority: 'High', action: 'Implement organization of information security' },
                { requirement: 'A.7.1.1', priority: 'High', action: 'Implement human resource security controls' },
                { requirement: 'A.8.1.1', priority: 'High', action: 'Implement asset management controls' },
                { requirement: 'A.9.1.1', priority: 'High', action: 'Implement access control policies' },
                { requirement: 'A.9.2.1', priority: 'High', action: 'Implement user access management' },
                { requirement: 'A.10.1.1', priority: 'High', action: 'Implement cryptography policies' },
                { requirement: 'A.11.1.1', priority: 'Medium', action: 'Implement physical and environmental security' },
                { requirement: 'A.12.1.1', priority: 'Medium', action: 'Implement operations security' },
                { requirement: 'A.13.1.1', priority: 'High', action: 'Implement communications security' },
                { requirement: 'A.14.1.1', priority: 'Medium', action: 'Implement system acquisition, development and maintenance' },
                { requirement: 'A.15.1.1', priority: 'Medium', action: 'Implement supplier relationship management' },
                { requirement: 'A.16.1.1', priority: 'High', action: 'Implement information security incident management' },
                { requirement: 'A.17.1.1', priority: 'Medium', action: 'Implement information security aspects of business continuity management' },
                { requirement: 'A.18.1.1', priority: 'High', action: 'Implement compliance controls' }
            ]
        };
        
        return rules[framework] || [];
    }

    evaluateComplianceRule(cvss, score, rule) {
        // Simplified compliance evaluation
        // In a real implementation, this would be more sophisticated
        if (rule.requirement.includes('6.1') && score >= 7.0) return true;
        if (rule.requirement.includes('6.2') && score >= 5.0) return true;
        if (rule.requirement.includes('11.2') && score >= 6.0) return true;
        if (rule.requirement.includes('Financial Data Integrity') && score >= 8.0) return true;
        if (rule.requirement.includes('System Availability') && score >= 6.0) return true;
        if (rule.requirement.includes('Access Controls') && score >= 7.0) return true;
        if (rule.requirement.includes('Data Confidentiality') && score >= 5.0) return true;
        if (rule.requirement.includes('Data Integrity') && score >= 5.0) return true;
        
        return false;
    }
}

// Make CVSSMetricsCalculator available globally for browser use
if (typeof window !== 'undefined') {
    window.CVSSMetricsCalculator = CVSSMetricsCalculator;
}

// Also make it available globally for Node.js testing
if (typeof global !== 'undefined') {
    global.CVSSMetricsCalculator = CVSSMetricsCalculator;
}

// Ensure global availability
if (typeof globalThis !== 'undefined') {
    globalThis.CVSSMetricsCalculator = CVSSMetricsCalculator;
}
