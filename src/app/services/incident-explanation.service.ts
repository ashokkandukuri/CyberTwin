import { Injectable } from "@angular/core";
import { Incident, IncidentStatus } from "@models/incident";
import { IncidentTimelineEntry } from "@models/incident-timeline-entry";
import { IncidentEvidence, EvidenceCategory } from "@models/incident-evidence";
import { AttackType } from "@models/attack-types";
import { MitigationType, MitigationStatus } from "@models/mitigation";

export interface IncidentExplanation {
    readonly incidentId: string;
    readonly summary: string;
    readonly detectionExplanation?: string;
    readonly riskExplanation?: string;
    readonly impactExplanation?: string;
    readonly attackExplanation?: string;
    readonly mitigationExplanation?: string;
    readonly recoveryExplanation?: string;
    readonly contributingFactors: readonly string[];
    readonly timelineSummary: readonly string[];
    readonly evidenceSummary: readonly string[];
}

/**
 * Generates deterministic, factual explanations of incidents.
 * Read-only, zero-mutation, entirely derived from immutable timeline and evidence state.
 */
@Injectable({ providedIn: "root" })
export class IncidentExplanationService {
    
    public explain(
        incident: Incident, 
        timeline: readonly IncidentTimelineEntry[], 
        evidence: readonly IncidentEvidence[]
    ): IncidentExplanation {
        
        // Categorize evidence
        const anomalies = evidence.filter(e => e.category === EvidenceCategory.ANOMALY);
        const risks = evidence.filter(e => e.category === EvidenceCategory.RISK);
        const impacts = evidence.filter(e => e.category === EvidenceCategory.IMPACT);
        const attacks = evidence.filter(e => e.category === EvidenceCategory.ATTACK);
        const mitigations = evidence.filter(e => e.category === EvidenceCategory.MITIGATION);
        const recoveries = evidence.filter(e => e.category === EvidenceCategory.RECOVERY);

        return {
            incidentId: incident.id,
            summary: this.generateSummary(incident, anomalies, mitigations, recoveries),
            detectionExplanation: this.generateDetection(anomalies),
            riskExplanation: this.generateRisk(risks),
            impactExplanation: this.generateImpact(impacts),
            attackExplanation: this.generateAttack(attacks),
            mitigationExplanation: this.generateMitigation(mitigations),
            recoveryExplanation: this.generateRecovery(incident.status, recoveries),
            contributingFactors: this.generateFactors(anomalies, risks, impacts),
            timelineSummary: this.generateTimelineSummary(timeline),
            evidenceSummary: this.generateEvidenceSummary(anomalies, risks, impacts, attacks, mitigations, recoveries)
        };
    }

    private generateSummary(
        incident: Incident,
        anomalies: IncidentEvidence[],
        mitigations: IncidentEvidence[],
        recoveries: IncidentEvidence[]
    ): string {
        let summary = "";

        // Context
        if (incident.attackType) {
            switch(incident.attackType) {
                case AttackType.DOS: summary += `Simulated DoS activity affected ${incident.twinId}. `; break;
                case AttackType.MQTT_FLOOD: summary += `Simulated MQTT flood activity affected ${incident.twinId}. `; break;
                case AttackType.SENSOR_SPOOF: summary += `Simulated sensor spoofing affected ${incident.twinId}. `; break;
                case AttackType.BRUTE_FORCE: summary += `Simulated brute force activity affected ${incident.twinId}. `; break;
                case AttackType.PORT_SCAN: summary += `Simulated port scan activity affected ${incident.twinId}. `; break;
                default: summary += `Simulated attack activity affected ${incident.twinId}. `;
            }
        } else {
            summary += `A security incident affected ${incident.twinId}. `;
        }

        // Detection
        if (anomalies.length > 0) {
            summary += "Anomalous behavior was detected. ";
        }

        // Severity
        if (incident.peakRiskLevel) {
            summary += `The resulting risk was assessed as ${incident.peakRiskLevel.toUpperCase()}. `;
        }
        if (incident.peakImpactLevel) {
            summary += `Operational impact increased to ${incident.peakImpactLevel.toUpperCase()}. `;
        }

        // Response
        if (mitigations.length > 0) {
            const applied = mitigations.find(m => m.mitigationType);
            if (applied?.mitigationType) {
                summary += `Simulated mitigation (${applied.mitigationType}) was applied. `;
            } else {
                summary += "Simulated mitigation was applied. ";
            }
        }

        switch (incident.status) {
            case IncidentStatus.INVESTIGATING:
            case IncidentStatus.OPEN:
                summary += "The attack was detected and is being analyzed.";
                break;
            case IncidentStatus.MITIGATED:
                summary += "Simulated mitigation was applied; incident recovery is in progress.";
                break;
            case IncidentStatus.RECOVERED:
                summary += "The simulated incident recovery was completed.";
                break;
        }

        return summary.trim();
    }

    private generateDetection(anomalies: IncidentEvidence[]): string | undefined {
        if (anomalies.length === 0) return "Detection evidence is not available.";
        
        // Find peak severity in evidence if possible, or just use the most recent
        const peak = anomalies[anomalies.length - 1]; // Temporal peak heuristic based on chron flow
        
        if (!peak.anomalySeverity) {
            return "Anomaly detection observed behavioral deviation from the baseline.";
        }

        let expl = `Anomaly detection identified ${peak.anomalySeverity.toUpperCase()} deviation from the established baseline.`;
        if (peak.contributingFeatures && peak.contributingFeatures.length > 0) {
            expl += ` The primary contributing observations were ${peak.contributingFeatures.join(", ")}.`;
        }

        return expl;
    }

    private generateRisk(risks: IncidentEvidence[]): string | undefined {
        if (risks.length === 0) return "Risk evidence is not available.";
        
        // Explain the peak risk, not the most recent (possibly lower) observation.
        // This keeps the narrative consistent with Incident.peakRiskLevel/peakRiskScore
        // shown in the incident header.
        const withScores = risks.filter(r => this.isValidNum(r.riskScore));
        const peak = withScores.length > 0
            ? withScores.reduce((best, current) =>
                current.riskScore! > best.riskScore! ? current : best, withScores[0])
            : risks[risks.length - 1];
        if (!peak.riskLevel) return "Risk level information was recorded but details are missing.";

        let expl = `Peak risk was assessed at ${peak.riskLevel.toUpperCase()} level`;
        if (this.isValidNum(peak.riskScore)) {
            expl += ` (score: ${peak.riskScore})`;
        }
        expl += ".";

        if (peak.riskFactors && peak.riskFactors.length > 0) {
            expl += ` Primary contributing risk factors included: ${peak.riskFactors.join(", ")}.`;
        }

        return expl;
    }

    private generateImpact(impacts: IncidentEvidence[]): string | undefined {
        if (impacts.length === 0) return "Operational impact evidence is not available.";
        
        const peak = impacts.reduce((best, current) => {
            const bestScore = this.isValidNum(best.impactScore) ? best.impactScore! : -1;
            const currentScore = this.isValidNum(current.impactScore) ? current.impactScore! : -1;
            return currentScore > bestScore ? current : best;
        }, impacts[0]);
        if (!peak.impactLevel) return "Impact level information was recorded but details are missing.";

        let expl = `Peak operational impact reached ${peak.impactLevel.toUpperCase()} level`;
        if (this.isValidNum(peak.impactScore)) {
            expl += ` (score: ${peak.impactScore})`;
        }
        expl += ".";

        if (peak.impactDimensions && peak.impactDimensions.length > 0) {
            expl += ` Primary impact dimensions observed: ${peak.impactDimensions.join(", ")}.`;
        }

        return expl;
    }

    private generateAttack(attacks: IncidentEvidence[]): string | undefined {
        if (attacks.length === 0) return "Attack evidence is not available.";
        
        const peak = attacks.find(a => a.attackType);
        if (!peak || !peak.attackType) return "Simulated attack activity was recorded without specific type classification.";

        switch(peak.attackType) {
            case AttackType.DOS:
                return "Simulated denial-of-service traffic was generated against the target.";
            case AttackType.MQTT_FLOOD:
                return "Simulated MQTT publish traffic was generated against the target.";
            case AttackType.SENSOR_SPOOF:
                return "Simulated sensor values were altered through the attack simulation.";
            case AttackType.BRUTE_FORCE:
                return "Simulated authentication attempts were generated against the target service.";
            case AttackType.PORT_SCAN:
                return "Simulated TCP SYN probes were generated across the configured port range.";
            default:
                return "Simulated attack activity was generated against the target.";
        }
    }

    private generateMitigation(mitigations: IncidentEvidence[]): string | undefined {
        if (mitigations.length === 0) return "Mitigation evidence is not available.";
        
        const applied = mitigations.find(m => m.mitigationType);
        if (!applied || !applied.mitigationType) return "Simulated mitigation was applied.";

        switch (applied.mitigationType) {
            case MitigationType.TRAFFIC_RATE_LIMIT:
                return "Simulated traffic rate limiting reduced the effective attack generation rate.";
            case MitigationType.SENSOR_VALIDATION:
                return "Simulated sensor validation suppressed untrusted spoofed sensor updates.";
            case MitigationType.AUTH_RATE_LIMIT:
                return "Simulated authentication rate limiting reduced the effective brute-force attempt rate.";
            case MitigationType.SCAN_RATE_LIMIT:
                return "Simulated scan rate limiting reduced the effective probe rate.";
            default:
                return `Simulated mitigation control (${applied.mitigationType}) was applied.`;
        }
    }

    private generateRecovery(status: IncidentStatus, recoveries: IncidentEvidence[]): string | undefined {
        if (status === IncidentStatus.RECOVERED) {
            return recoveries.some(r => r.mitigationStatus === MitigationStatus.RECOVERED)
                ? "The simulated incident recovery completed."
                : "The incident status is RECOVERED; recovery evidence is not available.";
        }
        if (status === IncidentStatus.MITIGATED) {
            return "Mitigation is applied; incident recovery is pending.";
        }
        return recoveries.some(r => r.mitigationStatus === MitigationStatus.VERIFYING)
            ? "Recovery has started; incident investigation is still active."
            : "Recovery has not completed.";
    }

    private generateFactors(
        anomalies: IncidentEvidence[], 
        risks: IncidentEvidence[], 
        impacts: IncidentEvidence[]
    ): readonly string[] {
        const factors = new Set<string>();

        for (const a of anomalies) {
            if (a.contributingFeatures) {
                for (const f of a.contributingFeatures) {
                    factors.add(`Feature anomaly: ${f}`);
                }
            }
        }

        for (const r of risks) {
            if (r.riskFactors) {
                for (const f of r.riskFactors) {
                    factors.add(`Risk factor: ${f}`);
                }
            }
        }

        for (const i of impacts) {
            if (i.impactDimensions) {
                for (const d of i.impactDimensions) {
                    factors.add(`Impact dimension: ${d}`);
                }
            }
        }

        return Array.from(factors);
    }

    private generateTimelineSummary(timeline: readonly IncidentTimelineEntry[]): readonly string[] {
        return timeline.map(t => `[${t.timestamp.toISOString()}] ${t.title}: ${t.summary}`);
    }

    private generateEvidenceSummary(
        anomalies: IncidentEvidence[],
        risks: IncidentEvidence[],
        impacts: IncidentEvidence[],
        attacks: IncidentEvidence[],
        mitigations: IncidentEvidence[],
        recoveries: IncidentEvidence[]
    ): readonly string[] {
        const cats: string[] = [];
        if (anomalies.length > 0) cats.push("Anomaly evidence");
        if (risks.length > 0) cats.push("Risk evidence");
        if (impacts.length > 0) cats.push("Impact evidence");
        if (attacks.length > 0) cats.push("Attack evidence");
        if (mitigations.length > 0) cats.push("Mitigation evidence");
        if (recoveries.length > 0) cats.push("Recovery evidence");
        
        return cats.length > 0 ? cats : ["No structured evidence available."];
    }

    private isValidNum(val: any): boolean {
        return typeof val === 'number' && !isNaN(val) && isFinite(val);
    }
}
