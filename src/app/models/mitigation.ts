/**
 * Types of simulated defensive controls in Phase 6.
 */
export enum MitigationType {
    TRAFFIC_RATE_LIMIT = "traffic_rate_limit",
    SENSOR_VALIDATION = "sensor_validation",
    AUTH_RATE_LIMIT = "auth_rate_limit",
    SCAN_RATE_LIMIT = "scan_rate_limit"
}

/**
 * Lifecycle status of a simulated mitigation instance.
 */
export enum MitigationStatus {
    RECOMMENDED = "recommended",
    APPLIED = "applied",
    VERIFYING = "verifying",
    RECOVERED = "recovered",
    FAILED = "failed",
    STOPPED = "stopped"
}

let mitigationIdCounter = 0;

/**
 * Generates a unique ID for a mitigation execution instance.
 */
export function generateMitigationId(): string {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
        return crypto.randomUUID();
    }
    mitigationIdCounter++;
    return `mitig-${Date.now()}-${mitigationIdCounter}`;
}

/**
 * Plain domain data representing one simulated mitigation instance.
 * Does NOT contain methods, services, timers, or node references.
 */
export interface MitigationExecution {
    /** Unique identifier for this mitigation instance */
    readonly id: string;
    
    /** The ID (MAC address) of the DigitalTwin this mitigation targets */
    readonly twinId: string;
    
    /** The type of defensive control applied */
    readonly type: MitigationType;
    
    /** Current lifecycle status */
    status: MitigationStatus;
    
    /** Related attack ID if this mitigation targets a specific attack */
    relatedAttackId?: string;
    
    /** Timestamp when the mitigation was created/recommended (Epoch ms) */
    readonly createdAt: number;
    
    /** Timestamp of the last status update (Epoch ms) */
    updatedAt: number;
}
