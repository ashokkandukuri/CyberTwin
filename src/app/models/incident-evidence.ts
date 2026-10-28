import { AnomalySeverity, AnomalyFeature } from "./anomaly";
import { RiskLevel } from "./risk";
import { ImpactLevel } from "./impact";
import { AttackType } from "./attack-types";
import { MitigationType, MitigationStatus } from "./mitigation";

/**
 * Classifies the type of factual evidence captured.
 */
export enum EvidenceCategory {
    ANOMALY = "anomaly",
    RISK = "risk",
    IMPACT = "impact",
    ATTACK = "attack",
    MITIGATION = "mitigation",
    RECOVERY = "recovery"
}

/**
 * Factual data snapshot explaining a state transition or security event.
 * Used to support explanations like "Packet rate deviated from baseline reaching HIGH severity".
 * 
 * Uses compact immutable snapshots instead of duplicating large complex service objects.
 */
export interface IncidentEvidence {
    readonly id: string;
    readonly incidentId: string;
    readonly timestamp: Date;
    readonly category: EvidenceCategory;
    readonly description: string;
    
    // --- Evidence Snapshots (Populated based on Category) ---
    
    // Anomaly data
    readonly anomalySeverity?: AnomalySeverity;
    readonly anomalyScore?: number;
    readonly contributingFeatures?: readonly AnomalyFeature[];
    
    // Risk data
    readonly riskScore?: number;
    readonly riskLevel?: RiskLevel;
    readonly riskFactors?: readonly string[];
    
    // Impact data
    readonly impactScore?: number;
    readonly impactLevel?: ImpactLevel;
    readonly impactDimensions?: readonly string[];
    
    // Attack data
    readonly attackType?: AttackType;
    readonly attackIntensity?: number;
    
    // Mitigation & Recovery data
    readonly mitigationType?: MitigationType;
    readonly mitigationStatus?: MitigationStatus;
}
