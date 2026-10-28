/**
 * Types of security events in the CyberTwin system.
 * Extensible: add new values without breaking existing code.
 */
export enum SecurityEventType {
    ANOMALY_DETECTED = "anomaly_detected",
    ANOMALY_CLEARED = "anomaly_cleared",
    ATTACK_STARTED = "attack_started",
    ATTACK_PROGRESS = "attack_progress",
    ATTACK_DETECTED = "attack_detected",
    ATTACK_STOPPED = "attack_stopped",
    ATTACK_FAILED = "attack_failed",
    ATTACK_COMPLETED = "attack_completed",
    DEVICE_DEGRADED = "device_degraded",
    DEVICE_COMPROMISED = "device_compromised",
    MITIGATION_RECOMMENDED = "mitigation_recommended",
    MITIGATION_APPLIED = "mitigation_applied",
    MITIGATION_STOPPED = "mitigation_stopped",
    RECOVERY_STARTED = "recovery_started",
    RECOVERY_COMPLETED = "recovery_completed",
    RECOVERY_FAILED = "recovery_failed",
    RISK_CHANGED = "risk_changed",
    IMPACT_CHANGED = "impact_changed",
    TWIN_CREATED = "twin_created",
    TWIN_REMOVED = "twin_removed",
    STATE_CHANGED = "state_changed",
}

/**
 * Severity levels for security events.
 */
export enum SecurityEventSeverity {
    INFO = "info",
    LOW = "low",
    MEDIUM = "medium",
    HIGH = "high",
    CRITICAL = "critical",
}

/**
 * Represents an immutable security event in the CyberTwin system.
 * Once created, a SecurityEvent should never be mutated.
 */
export interface SecurityEvent {
    /** Unique event identifier (UUID) */
    readonly id: string;
    /** Timestamp when the event occurred */
    readonly timestamp: Date;
    /** Type of security event */
    readonly type: SecurityEventType;
    /** Severity of the event */
    readonly severity: SecurityEventSeverity;
    /** MAC address of the source device */
    readonly source: string;
    /** MAC address of the target device (if applicable) */
    readonly target?: string;
    /** Human-readable description of the event */
    readonly description: string;
    /** Reference to a related attack execution ID (for future Phase 2 integration) */
    readonly relatedAttackId?: string;
    /** Additional metadata — frozen on creation */
    readonly metadata: Readonly<Record<string, string | number | boolean>>;
}

/** Auto-incrementing counter for unique event IDs */
let eventIdCounter = 0;

/**
 * Generates a unique event ID.
 * Uses crypto.randomUUID() when available, falls back to counter-based ID.
 */
function generateEventId(): string {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
        return crypto.randomUUID();
    }
    eventIdCounter++;
    return `evt-${Date.now()}-${eventIdCounter}`;
}

/**
 * Parameters required to create a SecurityEvent.
 * Omits auto-generated fields (id, timestamp).
 */
export interface CreateSecurityEventParams {
    readonly type: SecurityEventType;
    readonly severity: SecurityEventSeverity;
    readonly source: string;
    readonly target?: string;
    readonly description: string;
    readonly relatedAttackId?: string;
    readonly metadata?: Record<string, string | number | boolean>;
}

/**
 * Creates an immutable SecurityEvent.
 *
 * @param params Event creation parameters
 * @returns A frozen SecurityEvent instance
 */
export function createSecurityEvent(params: CreateSecurityEventParams): SecurityEvent {
    const event: SecurityEvent = {
        id: generateEventId(),
        timestamp: new Date(),
        type: params.type,
        severity: params.severity,
        source: params.source,
        target: params.target,
        description: params.description,
        relatedAttackId: params.relatedAttackId,
        metadata: Object.freeze({ ...(params.metadata ?? {}) }),
    };
    return Object.freeze(event);
}
