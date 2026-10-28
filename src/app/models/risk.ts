/**
 * CyberTwin Phase 4: Risk Scoring Data Models
 */

export const ANOMALY_MAX = 40;
export const ATTACK_MAX = 30;
export const TARGET_MAX = 15;
export const PERSISTENCE_MAX = 15;
export const TOTAL_MAX = 100;

export enum RiskLevel {
    LOW = "low",
    MEDIUM = "medium",
    HIGH = "high",
    CRITICAL = "critical"
}

export interface RiskFactor {
    readonly name: string;
    readonly contributionScore: number;
    readonly metadata: Readonly<Record<string, string | number>>;
}

export interface RiskAssessment {
    readonly twinId: string;
    readonly timestamp: Date;
    readonly totalScore: number;
    readonly level: RiskLevel;
    readonly factors: ReadonlyArray<RiskFactor>;
    readonly primaryFactorName: string;
    readonly explanation: string;
}
