import { AttackType } from "./attack-types";
import { RiskLevel } from "./risk";
import { ImpactLevel } from "./impact";
import { MitigationType, MitigationStatus } from "./mitigation";

/**
 * Status lifecycle of a security incident.
 * Separated from AttackStatus to support investigation workflow independently
 * of the raw attack simulation lifecycle.
 */
export enum IncidentStatus {
    OPEN = "open",
    INVESTIGATING = "investigating",
    MITIGATED = "mitigated",
    RECOVERED = "recovered",
    CLOSED = "closed"
}

/**
 * Represents a correlated security situation involving a Digital Twin.
 * Groups events, risk, impact, and mitigations into a single explainable narrative.
 */
export interface Incident {
    readonly id: string;
    readonly twinId: string;
    readonly createdAt: Date;
    readonly updatedAt: Date;
    readonly status: IncidentStatus;
    
    readonly title: string;
    readonly explanation?: string;
    
    // --- Correlated Context ---
    readonly attackId?: string;
    readonly attackType?: AttackType;
    
    readonly peakRiskLevel?: RiskLevel;
    readonly peakRiskScore?: number;
    
    readonly peakImpactLevel?: ImpactLevel;
    readonly peakImpactScore?: number;
    
    readonly mitigationId?: string;
    readonly mitigationType?: MitigationType;
    readonly mitigationStatus?: MitigationStatus;
    
    // --- Relational References ---
    readonly timelineEntryIds: readonly string[];
    readonly evidenceIds: readonly string[];
}
