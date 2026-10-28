import { Injectable } from "@angular/core";
import { MitigationExecution, MitigationStatus } from "@models/mitigation";
import { AnomalySeverity, AnomalyResult } from "@models/anomaly";
import { ImpactAssessment, ImpactLevel } from "@models/impact";

export enum RecoveryTransition {
    NONE = "none",
    VERIFYING = "verifying",
    RECOVERED = "recovered"
}

interface RecoveryTrackingState {
    ticks: number;
    twinId: string;
}

/**
 * Pure stateful evaluator for determining if a mitigated system has fully recovered.
 * Analyzes consecutive observations of healthy states to declare RECOVERED.
 * Deterministic. No external network or time dependencies.
 */
@Injectable({ providedIn: "root" })
export class RecoveryService {
    // Tracks consecutive healthy ticks per mitigation execution ID
    private _state = new Map<string, RecoveryTrackingState>();
    // Tracks healthy recovery for a twin when no mitigation execution exists.
    private _twinState = new Map<string, RecoveryTrackingState>();

    /**
     * Evaluates whether an applied mitigation has fully recovered the system.
     * Updates internal tracking and transitions the mitigation status if recovered.
     * 
     * @param mitigationExecution The mitigation to evaluate
     * @param anomalyState The latest AnomalyResult for the affected Twin
     * @param impactAssessment The latest ImpactAssessment for the affected Twin
     * @param relevantAttackActive Whether the attack that caused this mitigation is still running
     * @returns RecoveryTransition indicating the required status change
     */
    public evaluateRecovery(
        mitigationExecution: MitigationExecution,
        anomalyState: AnomalyResult | null,
        impactAssessment: ImpactAssessment | null,
        relevantAttackActive: boolean
    ): RecoveryTransition {
        // 1. Validate input state bounds
        if (!mitigationExecution || 
            (mitigationExecution.status !== MitigationStatus.APPLIED && 
             mitigationExecution.status !== MitigationStatus.VERIFYING)) {
            return RecoveryTransition.NONE;
        }

        // 2. Evaluate healthy conditions strictly
        const anomalyHealthy = anomalyState ? anomalyState.severity === AnomalySeverity.NORMAL : false;
        const impactHealthy = impactAssessment ? impactAssessment.level === ImpactLevel.LOW : false;

        const isHealthyTick = anomalyHealthy && impactHealthy && !relevantAttackActive;

        // 3. Fetch or initialize bounded state tracking
        const currentState = this._state.get(mitigationExecution.id) || { 
            ticks: 0, 
            twinId: mitigationExecution.twinId 
        };
        
        if (isHealthyTick) {
            currentState.ticks++;
            
            // RECOVERED strictly on the 5th consecutive healthy tick
            if (currentState.ticks >= 5) {
                // We leave the state entry temporarily for cleanup later, 
                // but bounded logic prevents it from mattering.
                this._state.set(mitigationExecution.id, currentState);
                return RecoveryTransition.RECOVERED;
            }

            // Transition to VERIFYING exactly once, on the first healthy tick.
            // The caller normally changes the execution status to VERIFYING immediately;
            // this guard also keeps the evaluator deterministic if called repeatedly with
            // an APPLIED snapshot by a unit test or alternate orchestrator.
            if (mitigationExecution.status === MitigationStatus.APPLIED && currentState.ticks === 1) {
                this._state.set(mitigationExecution.id, currentState);
                return RecoveryTransition.VERIFYING;
            }
        } else {
            // Any unhealthy condition immediately breaks the streak
            currentState.ticks = 0;
        }

        this._state.set(mitigationExecution.id, currentState);
        return RecoveryTransition.NONE;
    }

    /**
     * Evaluates recovery for an affected twin that has no active mitigation.
     * This uses the same strict five-tick gate so a completed attack cannot leave
     * the Digital Twin permanently marked UNDER_ATTACK merely because policy did
     * not recommend a control for that attack's impact.
     */
    public evaluateTwinRecovery(
        twinId: string,
        anomalyState: AnomalyResult | null,
        impactAssessment: ImpactAssessment | null,
        relevantAttackActive: boolean
    ): RecoveryTransition {
        const currentState = this._twinState.get(twinId) || { ticks: 0, twinId };
        const anomalyHealthy = anomalyState?.severity === AnomalySeverity.NORMAL;
        const impactHealthy = impactAssessment?.level === ImpactLevel.LOW;
        const isHealthyTick = anomalyHealthy && impactHealthy && !relevantAttackActive;

        if (!isHealthyTick) {
            currentState.ticks = 0;
            this._twinState.set(twinId, currentState);
            return RecoveryTransition.NONE;
        }

        currentState.ticks++;
        this._twinState.set(twinId, currentState);

        if (currentState.ticks >= 5) {
            return RecoveryTransition.RECOVERED;
        }
        return currentState.ticks === 1 ? RecoveryTransition.VERIFYING : RecoveryTransition.NONE;
    }

    public cleanupTwinRecovery(twinId: string): void {
        this._twinState.delete(twinId);
    }

    /**
     * Cleans up tracking state for a specific mitigation.
     */
    public cleanupForMitigation(mitigationId: string): void {
        this._state.delete(mitigationId);
    }

    /**
     * Cleans up tracking state for a specific Digital Twin when removed.
     */
    public cleanupForTwin(twinId: string): void {
        this.cleanupTwinRecovery(twinId);
        const toDelete: string[] = [];
        for (const [mitigationId, state] of this._state.entries()) {
            if (state.twinId === twinId) {
                toDelete.push(mitigationId);
            }
        }
        for (const id of toDelete) {
            this._state.delete(id);
        }
    }

    /**
     * Resets the entire recovery tracking state (e.g., when the network is reset).
     */
    public reset(): void {
        this._state.clear();
        this._twinState.clear();
    }
}
