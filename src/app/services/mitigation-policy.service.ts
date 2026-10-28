import { Injectable } from "@angular/core";
import { AttackExecution, AttackStatus } from "@models/attack-execution";
import { AttackType } from "@models/attack-types";
import { ImpactAssessment, ImpactLevel } from "@models/impact";
import { MitigationType } from "@models/mitigation";

/**
 * Clean, lightweight structure for a mitigation recommendation.
 */
export interface MitigationRecommendation {
    mitigationType: MitigationType;
    twinId: string;
    relatedAttackId?: string;
    relatedAttackType?: AttackType;
    reason: string;
}

/**
 * Pure policy layer that determines which defensive mitigation 
 * should be recommended for a given security context.
 * 
 * Side-effect free. Stateless. Deterministic.
 */
@Injectable({ providedIn: "root" })
export class MitigationPolicyService {
    
    /**
     * Evaluates the current security context to recommend mitigations.
     * 
     * @param twinId The targeted DigitalTwin ID
     * @param impact The latest ImpactAssessment (if any)
     * @param attacks List of all known attack executions
     * @returns Array of mitigation recommendations
     */
    public evaluate(
        twinId: string,
        impact: ImpactAssessment | null,
        attacks: AttackExecution[] | null | undefined
    ): MitigationRecommendation[] {
        // Edge cases: safely handle missing impact or attacks
        if (!impact) return [];
        if (!attacks || !Array.isArray(attacks) || attacks.length === 0) return [];
        
        const recommendations: MitigationRecommendation[] = [];
        
        // The caller may provide active attacks plus a short-lived completed attack
        // context. A completed context is valid here because impact is telemetry-
        // driven and can become visible on the tick immediately after completion.
        const mitigationCandidates = attacks.filter(a =>
            a.status === AttackStatus.RUNNING ||
            a.status === AttackStatus.DETECTED ||
            a.status === AttackStatus.COMPLETED
        );

        if (mitigationCandidates.length === 0) return [];

        for (const attack of mitigationCandidates) {
            const type = attack.config?.type;
            if (!type) continue;
            
            const prefix = this._getAttackPrefix(type);

            if (type === AttackType.DOS) {
                const perfLevel = this._determineLevel(impact.performanceImpact);
                if (this._isAtLeast(perfLevel, ImpactLevel.MEDIUM)) {
                    recommendations.push({
                        mitigationType: MitigationType.TRAFFIC_RATE_LIMIT,
                        twinId,
                        relatedAttackId: attack.id,
                        relatedAttackType: type,
                        reason: `${prefix} with ${perfLevel.toUpperCase()} performance impact`
                    });
                }
            } 
            else if (type === AttackType.MQTT_FLOOD) {
                const perfLevel = this._determineLevel(impact.performanceImpact);
                if (this._isAtLeast(perfLevel, ImpactLevel.MEDIUM)) {
                    recommendations.push({
                        mitigationType: MitigationType.TRAFFIC_RATE_LIMIT,
                        twinId,
                        relatedAttackId: attack.id,
                        relatedAttackType: type,
                        reason: `${prefix} with ${perfLevel.toUpperCase()} performance impact`
                    });
                }
            } 
            else if (type === AttackType.SENSOR_SPOOF) {
                const integLevel = this._determineLevel(impact.integrityImpact);
                if (this._isAtLeast(integLevel, ImpactLevel.MEDIUM)) {
                    recommendations.push({
                        mitigationType: MitigationType.SENSOR_VALIDATION,
                        twinId,
                        relatedAttackId: attack.id,
                        relatedAttackType: type,
                        reason: `${prefix} with ${integLevel.toUpperCase()} integrity impact`
                    });
                }
            } 
            else if (type === AttackType.BRUTE_FORCE) {
                const authLevel = this._determineLevel(impact.authenticationImpact);
                if (this._isAtLeast(authLevel, ImpactLevel.MEDIUM)) {
                    recommendations.push({
                        mitigationType: MitigationType.AUTH_RATE_LIMIT,
                        twinId,
                        relatedAttackId: attack.id,
                        relatedAttackType: type,
                        reason: `${prefix} with ${authLevel.toUpperCase()} authentication impact`
                    });
                }
            } 
            else if (type === AttackType.PORT_SCAN) {
                // Scan probes are evaluated in their own impact dimension. The
                // prior HIGH overall gate was unreachable: the existing
                // performance dimension tops out at 40 and scans have no auth or
                // integrity contribution. MEDIUM keeps the same dimension gate
                // used by the other attack-specific controls.
                const securityLevel = this._determineLevel(impact.securityImpact);
                if (this._isAtLeast(securityLevel, ImpactLevel.MEDIUM)) {
                    recommendations.push({
                        mitigationType: MitigationType.SCAN_RATE_LIMIT,
                        twinId,
                        relatedAttackId: attack.id,
                        relatedAttackType: type,
                        reason: `${prefix} with ${securityLevel.toUpperCase()} security impact`
                    });
                }
            }
        }
        
        return recommendations;
    }

    private _getAttackPrefix(type: AttackType): string {
        switch (type) {
            case AttackType.DOS: return "DoS attack";
            case AttackType.MQTT_FLOOD: return "MQTT flood";
            case AttackType.SENSOR_SPOOF: return "Sensor spoof";
            case AttackType.BRUTE_FORCE: return "Brute force";
            case AttackType.PORT_SCAN: return "Port scan";
            default: return "Unknown attack";
        }
    }

    /**
     * Determines ImpactLevel from a raw numerical score (0-100).
     */
    private _determineLevel(score: number): ImpactLevel {
        if (typeof score !== "number" || !Number.isFinite(score)) return ImpactLevel.LOW;
        if (score >= 80) return ImpactLevel.CRITICAL;
        if (score >= 50) return ImpactLevel.HIGH;
        if (score >= 20) return ImpactLevel.MEDIUM;
        return ImpactLevel.LOW;
    }

    /**
     * Compares two ImpactLevels hierarchically.
     * Returns true if `actual` >= `threshold`.
     */
    private _isAtLeast(actual: ImpactLevel, threshold: ImpactLevel): boolean {
        const levels: Record<string, number> = {
            [ImpactLevel.LOW]: 1,
            [ImpactLevel.MEDIUM]: 2,
            [ImpactLevel.HIGH]: 3,
            [ImpactLevel.CRITICAL]: 4
        };
        
        return (levels[actual] || 0) >= (levels[threshold] || 0);
    }
}
