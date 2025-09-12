/**
 * Campbell Murray - Sodium Cyber Ltd - 2025
 * CVSS-Based Management Metrics Implementation
 * 
 * This module provides practical implementations of CVSS-based management metrics
 * for technical debt, risk matrix, remediation effort, and compliance mapping.
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
        
        return components;
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
     * Generate dynamic risk matrix
     * @param {Array} vulnerabilities - Array of vulnerability objects
     * @returns {Object} Risk matrix data
     */
    generateRiskMatrix(vulnerabilities) {
        const matrix = {
            'Critical-High': [],
            'Critical-Medium': [],
            'High-High': [],
            'High-Medium': [],
            'Medium-Medium': [],
            'Medium-Low': [],
            'Low-Low': []
        };
        
        vulnerabilities.forEach(vuln => {
            const cvss = this.parseCVSSVector(vuln.vector);
            
            // Calculate likelihood (exploitability + temporal factors)
            const exploitability = (this.weights.AV[cvss.AV] + this.weights.AC[cvss.AC] + 
                                  this.weights.AT[cvss.AT] + this.weights.PR[cvss.PR] + 
                                  this.weights.UI[cvss.UI]) / 5;
            
            // Calculate temporal factors, handling missing components
            let temporalSum = 0;
            let temporalCount = 0;
            
            if (cvss.E && this.weights.E[cvss.E] !== undefined) {
                temporalSum += this.weights.E[cvss.E];
                temporalCount++;
            }
            if (cvss.AU && this.weights.AU[cvss.AU] !== undefined) {
                temporalSum += this.weights.AU[cvss.AU];
                temporalCount++;
            }
            if (cvss.R && this.weights.R[cvss.R] !== undefined) {
                temporalSum += this.weights.R[cvss.R];
                temporalCount++;
            }
            
            const temporal = temporalCount > 0 ? temporalSum / temporalCount : 1.0;
            
            const likelihood = (exploitability + temporal) / 2;
            
            // Calculate impact (CIA average)
            const impact = (this.weights.VC[cvss.VC] + this.weights.VI[cvss.VI] + 
                          this.weights.VA[cvss.VA]) / 3;
            
            // Determine risk level
            const riskLevel = this.determineRiskLevel(likelihood, impact);
            matrix[riskLevel].push({
                ...vuln,
                likelihood: Math.round(likelihood * 100) / 100,
                impact: Math.round(impact * 100) / 100
            });
        });
        
        return matrix;
    }

    /**
     * Map vulnerabilities to compliance requirements
     * @param {Array} vulnerabilities - Array of vulnerability objects
     * @param {string} framework - Compliance framework ('PCI', 'SOX', 'HIPAA', 'GDPR')
     * @returns {Object} Compliance mapping results
     */
    mapCompliance(vulnerabilities, framework = 'PCI') {
        const complianceRules = this.getComplianceRules(framework);
        const results = {
            totalVulnerabilities: vulnerabilities.length,
            compliantVulnerabilities: 0,
            nonCompliantVulnerabilities: 0,
            complianceScore: 0,
            violationsByRequirement: {},
            recommendations: []
        };
        
        vulnerabilities.forEach(vuln => {
            const cvss = this.parseCVSSVector(vuln.vector);
            let isCompliant = true;
            let violatedRequirements = [];
            
            // Check each compliance rule
            Object.keys(complianceRules).forEach(requirement => {
                const rule = complianceRules[requirement];
                if (rule(cvss)) {
                    violatedRequirements.push(requirement);
                    isCompliant = false;
                }
            });
            
            if (isCompliant) {
                results.compliantVulnerabilities++;
            } else {
                results.nonCompliantVulnerabilities++;
                violatedRequirements.forEach(req => {
                    results.violationsByRequirement[req] = (results.violationsByRequirement[req] || 0) + 1;
                });
            }
        });
        
        results.complianceScore = Math.round((results.compliantVulnerabilities / results.totalVulnerabilities) * 100);
        results.recommendations = this.generateComplianceRecommendations(results.violationsByRequirement, framework);
        
        return results;
    }

    /**
     * Calculate security posture metrics
     * @param {Array} vulnerabilities - Array of vulnerability objects
     * @returns {Object} Security posture metrics
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
            averageRisk: Math.round(averageRisk * 100) / 100,
            networkExposureScore: Math.round(networkExposureScore * 100) / 100,
            privilegeRiskScore: Math.round(privilegeRiskScore * 100) / 100,
            maturityIndex: Math.round(maturityIndex),
            totalVulnerabilities: vulnerabilities.length,
            controlledVulnerabilities,
            riskDistribution: this.calculateRiskDistribution(vulnerabilities)
        };
    }

    // Helper methods
    getDaysSinceDisclosure(disclosureDate) {
        if (!disclosureDate) return 0;
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

    determineRiskLevel(likelihood, impact) {
        if (likelihood >= 0.8 && impact >= 0.8) return 'Critical-High';
        if (likelihood >= 0.6 && impact >= 0.8) return 'Critical-Medium';
        if (likelihood >= 0.8 && impact >= 0.6) return 'High-High';
        if (likelihood >= 0.6 && impact >= 0.6) return 'High-Medium';
        if (likelihood >= 0.4 && impact >= 0.4) return 'Medium-Medium';
        if (likelihood >= 0.4 && impact >= 0.2) return 'Medium-Low';
        return 'Low-Low';
    }

    getComplianceRules(framework) {
        const rules = {
            PCI: {
                'Requirement 6.1': (cvss) => cvss.AC === 'L' && cvss.AV === 'N',
                'Requirement 6.2': (cvss) => cvss.VC === 'H' || cvss.VI === 'H',
                'Requirement 11.2': (cvss) => cvss.AV === 'N' && cvss.AC === 'L'
            },
            SOX: {
                'Financial Data Integrity': (cvss) => cvss.VI === 'H',
                'System Availability': (cvss) => cvss.VA === 'H',
                'Access Controls': (cvss) => cvss.PR === 'N' || cvss.PR === 'L'
            },
            HIPAA: {
                'Data Confidentiality': (cvss) => cvss.VC === 'H',
                'Data Integrity': (cvss) => cvss.VI === 'H',
                'System Availability': (cvss) => cvss.VA === 'H'
            }
        };
        
        return rules[framework] || {};
    }

    generateComplianceRecommendations(violations, framework) {
        const recommendations = [];
        
        Object.keys(violations).forEach(requirement => {
            const count = violations[requirement];
            recommendations.push({
                requirement,
                violationCount: count,
                priority: count > 5 ? 'High' : count > 2 ? 'Medium' : 'Low',
                action: this.getComplianceAction(requirement, framework)
            });
        });
        
        return recommendations.sort((a, b) => b.violationCount - a.violationCount);
    }

    getComplianceAction(requirement, framework) {
        const actions = {
            'Requirement 6.1': 'Implement secure coding practices and regular security testing',
            'Requirement 6.2': 'Apply security patches and updates promptly',
            'Requirement 11.2': 'Conduct regular vulnerability scans and penetration testing',
            'Financial Data Integrity': 'Implement data integrity controls and monitoring',
            'System Availability': 'Implement high availability and disaster recovery measures',
            'Access Controls': 'Strengthen authentication and authorization mechanisms'
        };
        
        return actions[requirement] || 'Review and address compliance requirements';
    }

    calculateDebtTrend(vulnerabilities) {
        // Simple trend calculation based on disclosure dates
        const now = new Date();
        const sixMonthsAgo = new Date(now.getTime() - (6 * 30 * 24 * 60 * 60 * 1000));
        
        const recent = vulnerabilities.filter(v => new Date(v.disclosureDate) > sixMonthsAgo).length;
        const older = vulnerabilities.filter(v => new Date(v.disclosureDate) <= sixMonthsAgo).length;
        
        return {
            recentVulnerabilities: recent,
            olderVulnerabilities: older,
            trend: recent > older ? 'Increasing' : 'Decreasing'
        };
    }

    calculateResourceRequirements(totalEffort) {
        return {
            personDays: Math.round(totalEffort),
            teamWeeks: Math.round(totalEffort / 5),
            teamMonths: Math.round(totalEffort / 20),
            recommendedTeamSize: Math.ceil(totalEffort / 30) // Assuming 30 days per person per month
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

    /**
     * Cluster vulnerabilities by CVSS vector similarity
     * @param {Array} vulnerabilities - Array of vulnerability objects
     * @param {number} threshold - Similarity threshold (0-1)
     * @returns {Array} Array of clusters
     */
    clusterVulnerabilities(vulnerabilities, threshold = 0.8) {
        const clusters = [];
        
        vulnerabilities.forEach(vuln => {
            const cvss = this.parseCVSSVector(vuln.vector);
            let assigned = false;
            
            clusters.forEach(cluster => {
                if (this.calculateSimilarity(cvss, cluster.centroid) >= threshold) {
                    cluster.vulnerabilities.push(vuln);
                    assigned = true;
                }
            });
            
            if (!assigned) {
                clusters.push({
                    centroid: cvss,
                    vulnerabilities: [vuln]
                });
            }
        });
        
        return clusters;
    }

    /**
     * Calculate similarity between two CVSS vectors
     * @param {Object} vector1 - First CVSS vector
     * @param {Object} vector2 - Second CVSS vector
     * @returns {number} Similarity score (0-1)
     */
    calculateSimilarity(vector1, vector2) {
        const components = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA'];
        let matches = 0;
        
        components.forEach(comp => {
            if (vector1[comp] === vector2[comp]) {
                matches++;
            }
        });
        
        return matches / components.length;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CVSSMetricsCalculator;
} else if (typeof window !== 'undefined') {
    window.CVSSMetricsCalculator = CVSSMetricsCalculator;
}
