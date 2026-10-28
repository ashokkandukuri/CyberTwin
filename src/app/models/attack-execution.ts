import { AttackConfig } from "./attack-types";

/**
 * Status of an attack execution.
 * Phase 2 explicitly does not auto-transition to DETECTED, MITIGATED, RECOVERED.
 */
export enum AttackStatus {
    CREATED = "created",
    CONFIGURED = "configured",
    RUNNING = "running",
    DETECTED = "detected", // Future phases
    MITIGATED = "mitigated", // Future phases
    RECOVERED = "recovered", // Future phases
    COMPLETED = "completed",
    STOPPED = "stopped",
    FAILED = "failed",
}

/**
 * Valid state transitions for AttackStatus.
 */
const VALID_TRANSITIONS: ReadonlyMap<AttackStatus, ReadonlySet<AttackStatus>> = new Map<AttackStatus, Set<AttackStatus>>([
    [AttackStatus.CREATED, new Set<AttackStatus>([
        AttackStatus.CONFIGURED,
        AttackStatus.FAILED,
    ])],
    [AttackStatus.CONFIGURED, new Set<AttackStatus>([
        AttackStatus.RUNNING,
        AttackStatus.FAILED,
    ])],
    [AttackStatus.RUNNING, new Set<AttackStatus>([
        AttackStatus.COMPLETED,
        AttackStatus.STOPPED,
        AttackStatus.FAILED,
        AttackStatus.DETECTED, // Supported for future, but unused in Phase 2 auto-transitions
    ])],
    [AttackStatus.DETECTED, new Set<AttackStatus>([
        AttackStatus.MITIGATED,
        AttackStatus.COMPLETED,
        AttackStatus.STOPPED,
        AttackStatus.FAILED,
    ])],
    [AttackStatus.MITIGATED, new Set<AttackStatus>([
        AttackStatus.RECOVERED,
        AttackStatus.COMPLETED,
        AttackStatus.STOPPED,
        AttackStatus.FAILED,
    ])],
    [AttackStatus.RECOVERED, new Set<AttackStatus>([
        AttackStatus.COMPLETED,
        AttackStatus.STOPPED,
    ])],
    // Terminal states - no transitions out
    [AttackStatus.COMPLETED, new Set<AttackStatus>()],
    [AttackStatus.STOPPED, new Set<AttackStatus>()],
    [AttackStatus.FAILED, new Set<AttackStatus>()],
]);

export function isValidAttackTransition(from: AttackStatus, to: AttackStatus): boolean {
    if (from === to) return true;
    const allowed = VALID_TRANSITIONS.get(from);
    return allowed !== undefined && allowed.has(to);
}

let executionIdCounter = 0;
function generateExecutionId(): string {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
        return crypto.randomUUID();
    }
    executionIdCounter++;
    return `atk-exec-${Date.now()}-${executionIdCounter}`;
}

/**
 * Represents the execution lifecycle of a simulated attack.
 */
export class AttackExecution {
    public readonly id: string;
    public readonly config: AttackConfig;
    public readonly createdAt: Date;
    
    private _status: AttackStatus;
    public get status(): AttackStatus {
        return this._status;
    }

    private _generatedPacketCount: number = 0;
    public get generatedPacketCount(): number {
        return this._generatedPacketCount;
    }

    private _lastUpdate: Date;
    public get lastUpdate(): Date {
        return this._lastUpdate;
    }
    
    public intervalHandle?: ReturnType<typeof setInterval>;
    public timeoutHandle?: ReturnType<typeof setTimeout>;

    constructor(config: AttackConfig) {
        this.id = generateExecutionId();
        this.config = config;
        this.createdAt = new Date();
        this._lastUpdate = new Date();
        this._status = AttackStatus.CREATED;
    }

    public transitionTo(newStatus: AttackStatus): boolean {
        if (!isValidAttackTransition(this._status, newStatus)) {
            return false;
        }
        this._status = newStatus;
        this._lastUpdate = new Date();
        return true;
    }

    public recordPacketsGenerated(count: number): void {
        this._generatedPacketCount += count;
        this._lastUpdate = new Date();
    }
}
