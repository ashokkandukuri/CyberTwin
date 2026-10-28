import { Injectable } from "@angular/core";
import { MitigationExecution, MitigationStatus, MitigationType, generateMitigationId } from "@models/mitigation";
import { MitigationRecommendation } from "./mitigation-policy.service";
import { AttackType } from "@models/attack-types";

/**
 * Manages the simulated execution of mitigation defensive controls.
 * Applies bounded, reversible effects to attacks without directly mutating telemetry.
 */
@Injectable({ providedIn: "root" })
export class MitigationEngineService {
    private _executions = new Map<string, MitigationExecution>();

    constructor() {}

    /**
     * Gets all mitigations currently managed.
     */
    public get mitigations(): MitigationExecution[] {
        return Array.from(this._executions.values());
    }

    /**
     * Applies a mitigation recommendation, returning the created execution state.
     */
    public applyMitigation(recommendation: MitigationRecommendation): MitigationExecution | null {
        // 1. Related attack validation based purely on the recommendation structure
        if (recommendation.relatedAttackId && recommendation.relatedAttackType) {
            // Validate mitigation type matches attack type using the policy-provided type
            if (!this._isValidMitigationForAttack(recommendation.mitigationType, recommendation.relatedAttackType)) {
                return null;
            }
        }

        // 3. Idempotency: Do not duplicate identical active mitigations
        const existing = this.mitigations.find(m => 
            m.twinId === recommendation.twinId && 
            m.type === recommendation.mitigationType && 
            m.relatedAttackId === recommendation.relatedAttackId &&
            (m.status === MitigationStatus.APPLIED || m.status === MitigationStatus.VERIFYING)
        );
        
        if (existing) {
            return existing;
        }

        // 4. Create new mitigation execution
        const execution: MitigationExecution = {
            id: generateMitigationId(),
            twinId: recommendation.twinId,
            type: recommendation.mitigationType,
            status: MitigationStatus.APPLIED,
            relatedAttackId: recommendation.relatedAttackId,
            createdAt: Date.now(),
            updatedAt: Date.now()
        };

        this._executions.set(execution.id, execution);
        
        return execution;
    }

    private _isValidMitigationForAttack(mitigationType: MitigationType, attackType: AttackType): boolean {
        switch (mitigationType) {
            case MitigationType.TRAFFIC_RATE_LIMIT:
                return attackType === AttackType.DOS || attackType === AttackType.MQTT_FLOOD;
            case MitigationType.SENSOR_VALIDATION:
                return attackType === AttackType.SENSOR_SPOOF;
            case MitigationType.AUTH_RATE_LIMIT:
                return attackType === AttackType.BRUTE_FORCE;
            case MitigationType.SCAN_RATE_LIMIT:
                return attackType === AttackType.PORT_SCAN;
            default:
                return false;
        }
    }

    /**
     * Called by AttackEngineService to consult the mitigation factor for an active attack.
     * Returns a bounded multiplier (e.g. 0.5 for 50% reduction). 1.0 means no mitigation.
     */
    public getMitigationFactor(attackId: string, mitigationType: MitigationType): number {
        const hasActiveMitigation = this.mitigations.some(m => 
            m.relatedAttackId === attackId && 
            m.type === mitigationType &&
            (m.status === MitigationStatus.APPLIED || m.status === MitigationStatus.VERIFYING)
        );

        if (hasActiveMitigation) {
            // Apply a bounded 50% reduction
            return 0.5;
        }
        
        return 1.0;
    }

    /**
     * Called by AttackEngineService to determine if sensor spoofing should be suppressed.
     */
    public isSensorSpoofSuppressed(attackId: string): boolean {
        return this.mitigations.some(m => 
            m.relatedAttackId === attackId && 
            m.type === MitigationType.SENSOR_VALIDATION &&
            (m.status === MitigationStatus.APPLIED || m.status === MitigationStatus.VERIFYING)
        );
    }

    /**
     * Manual cleanup of a specific mitigation.
     */
    public stopMitigation(id: string): void {
        const m = this._executions.get(id);
        if (m && (m.status === MitigationStatus.APPLIED || m.status === MitigationStatus.VERIFYING)) {
            m.status = MitigationStatus.STOPPED;
            m.updatedAt = Date.now();
        }
    }

    /**
     * Transitions a mitigation execution to a new status securely.
     */
    public transitionStatus(id: string, status: MitigationStatus): void {
        const m = this._executions.get(id);
        if (m) {
            m.status = status;
            m.updatedAt = Date.now();
        }
    }

    /**
     * Cleans up mitigations dependent on a stopped/completed attack.
     */
    public cleanupForAttack(attackId: string): void {
        for (const m of this._executions.values()) {
            if (m.relatedAttackId === attackId && 
                (m.status === MitigationStatus.APPLIED || m.status === MitigationStatus.VERIFYING)) {
                m.status = MitigationStatus.STOPPED;
                m.updatedAt = Date.now();
            }
        }
    }

    /**
     * Cleans up mitigations dependent on a removed twin.
     */
    public cleanupForTwin(twinId: string): void {
        for (const m of this._executions.values()) {
            if (m.twinId === twinId && 
                (m.status === MitigationStatus.APPLIED || m.status === MitigationStatus.VERIFYING)) {
                m.status = MitigationStatus.STOPPED;
                m.updatedAt = Date.now();
            }
        }
    }

    /**
     * Completely resets the mitigation engine (e.g., when changing networks).
     */
    public reset(): void {
        this._executions.clear();
    }
}
