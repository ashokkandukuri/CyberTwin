import { Injectable } from "@angular/core";
import { DigitalTwin } from "@models/digital-twin";
import { AnomalyResult } from "@models/anomaly";
import { AttackExecution, AttackStatus } from "@models/attack-execution";
import { NodeType } from "@models/node";
import { 
    RiskLevel, 
    RiskFactor, 
    RiskAssessment, 
    ANOMALY_MAX, 
    ATTACK_MAX, 
    TARGET_MAX, 
    PERSISTENCE_MAX, 
    TOTAL_MAX 
} from "@models/risk";

/**
 * Service responsible for deterministic risk scoring.
 * Calculates RiskAssessment passively without modifying state.
 */
@Injectable({ providedIn: "root" })
export class RiskScoringService {

    /**
     * Evaluates a fresh, immutable RiskAssessment snapshot.
     */
    public evaluateRisk(
        twin: DigitalTwin,
        anomalyResult: AnomalyResult,
        persistenceTicks: number,
        activeAttack?: AttackExecution | null
    ): RiskAssessment {
        
        // 1. Anomaly Contribution
        const validAnomalyScore = Number.isFinite(anomalyResult.score) ? Math.max(0, anomalyResult.score) : 0;
        const anomalyContribution = Math.max(0, Math.min(ANOMALY_MAX, validAnomalyScore * 4));
        
        const anomalyFactor: RiskFactor = {
            name: "Anomaly Magnitude",
            contributionScore: anomalyContribution,
            metadata: {
                rawScore: validAnomalyScore,
                severity: anomalyResult.severity
            }
        };

        // 2. Attack Context Contribution
        let attackContribution = 0;
        let attackMetadata: Record<string, string | number> = { active: 0 };
        
        if (activeAttack && activeAttack.status !== AttackStatus.STOPPED && activeAttack.status !== AttackStatus.COMPLETED) {
            const intensity = Number.isFinite(activeAttack.config.intensity) 
                ? Math.max(1, Math.min(10, activeAttack.config.intensity))
                : 1;
                
            attackContribution = Math.max(0, Math.min(ATTACK_MAX, 10 + (intensity * 2)));
            attackMetadata = {
                active: 1,
                attackId: activeAttack.id,
                type: activeAttack.config.type,
                intensity: intensity
            };
        }

        const attackFactor: RiskFactor = {
            name: "Active Simulated Attack",
            contributionScore: attackContribution,
            metadata: attackMetadata
        };

        // 3. Target Criticality Contribution
        // Use purely intrinsic device criticality to avoid double-counting anomaly state.
        let targetContribution = 5; // Default for Device / Sensor / Computer
        if (NodeType.RouterTypes.includes(twin.deviceType)) {
            targetContribution = 15;
        }
        
        targetContribution = Math.max(0, Math.min(TARGET_MAX, targetContribution));

        const targetFactor: RiskFactor = {
            name: "Target Criticality",
            contributionScore: targetContribution,
            metadata: {
                deviceType: twin.deviceType
            }
        };

        // 4. Persistence Contribution
        const validPersistence = Number.isFinite(persistenceTicks) ? Math.max(0, persistenceTicks) : 0;
        const persistenceContribution = Math.max(0, Math.min(PERSISTENCE_MAX, validPersistence));

        const persistenceFactor: RiskFactor = {
            name: "Persistence",
            contributionScore: persistenceContribution,
            metadata: {
                ticks: validPersistence
            }
        };

        // Total Score Calculation
        const rawScore = anomalyContribution + attackContribution + targetContribution + persistenceContribution;
        let totalScore = 0;
        if (Number.isFinite(rawScore)) {
            totalScore = Math.max(0, Math.min(TOTAL_MAX, rawScore));
        }

        // Risk Level Mapping
        const level = this._mapScoreToLevel(totalScore);

        // Factors array & deterministic primary factor tie-breaking
        const factors = [anomalyFactor, attackFactor, targetFactor, persistenceFactor].sort((a, b) => {
            if (b.contributionScore === a.contributionScore) {
                // Tie-breaking priority order
                const order = ["Anomaly Magnitude", "Active Simulated Attack", "Target Criticality", "Persistence"];
                return order.indexOf(a.name) - order.indexOf(b.name);
            }
            return b.contributionScore - a.contributionScore;
        });

        const primaryFactor = factors[0];

        // Deterministic human-readable explanation
        const explanation = `Risk level evaluated as ${level.toUpperCase()} (${totalScore}/${TOTAL_MAX}). Primary driver: ${primaryFactor.name} contributing ${primaryFactor.contributionScore} points.`;

        return {
            twinId: twin.id,
            timestamp: new Date(),
            totalScore,
            level,
            factors,
            primaryFactorName: primaryFactor.name,
            explanation
        };
    }

    /**
     * Maps deterministic bounds to risk levels.
     */
    private _mapScoreToLevel(score: number): RiskLevel {
        if (score >= 80) return RiskLevel.CRITICAL;
        if (score >= 50) return RiskLevel.HIGH;
        if (score >= 25) return RiskLevel.MEDIUM;
        return RiskLevel.LOW;
    }
}
