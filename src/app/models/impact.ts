export enum ImpactLevel {
    LOW = "low",
    MEDIUM = "medium",
    HIGH = "high",
    CRITICAL = "critical"
}

export interface ImpactAssessment {
    twinId: string;
    timestamp: number;
    overallScore: number;
    level: ImpactLevel;
    performanceImpact: number;
    integrityImpact: number;
    authenticationImpact: number;
    securityImpact: number;
    potentialBlastRadius: number;
    primaryImpactDimension: string;
}
