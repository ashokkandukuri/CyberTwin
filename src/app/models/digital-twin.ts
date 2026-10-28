import { DeviceSecurityState, isValidTransition } from "@models/device-state";
import { NodeType } from "@models/node";
import {
    TwinTelemetry,
    TelemetryBaseline,
    createTelemetry,
    getBaselineForType,
    applyDrift,
    clampTelemetry,
} from "@models/telemetry";
import { RiskAssessment } from "@models/risk";

/** Auto-incrementing counter for twin IDs when crypto.randomUUID is unavailable */
let twinIdCounter = 0;

/**
 * Generates a unique twin ID.
 */
function generateTwinId(): string {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
        return crypto.randomUUID();
    }
    twinIdCounter++;
    return `twin-${Date.now()}-${twinIdCounter}`;
}

/**
 * Represents a Digital Twin of an IoT device or network node.
 *
 * The DigitalTwin does NOT hold a direct reference to the Node object.
 * It references the node by its MAC address (stable identifier).
 * This prevents circular references and keeps the simulation and
 * security domains separated.
 */
export class DigitalTwin {
    /** Unique identifier for this twin */
    public readonly id: string;

    /** MAC address of the associated node (stable reference) */
    public readonly nodeMac: string;

    /** Type of the device this twin represents */
    public readonly deviceType: NodeType;

    /** IP address — updated on each telemetry tick from the live node */
    private _ip: string | undefined;
    public get ip(): string | undefined {
        return this._ip;
    }

    /** Current operational/security state */
    private _state: DeviceSecurityState;
    public get state(): DeviceSecurityState {
        return this._state;
    }

    /** Current telemetry snapshot */
    private _telemetry: TwinTelemetry;
    public get telemetry(): TwinTelemetry {
        return this._telemetry;
    }

    /** Reference to a current attack execution ID (null if no active attack) */
    private _currentAttackId: string | null;
    public get currentAttackId(): string | null {
        return this._currentAttackId;
    }

    /** Latest calculated risk assessment */
    private _latestRiskAssessment: RiskAssessment | null = null;
    public get latestRiskAssessment(): RiskAssessment | null {
        return this._latestRiskAssessment;
    }

    public setLatestRiskAssessment(assessment: RiskAssessment | null): void {
        this._latestRiskAssessment = assessment;
    }

    /** Latest calculated impact assessment */
    private _latestImpactAssessment: import("@models/impact").ImpactAssessment | null = null;
    public get latestImpactAssessment(): import("@models/impact").ImpactAssessment | null {
        return this._latestImpactAssessment;
    }

    public setLatestImpactAssessment(assessment: import("@models/impact").ImpactAssessment | null): void {
        this._latestImpactAssessment = assessment;
    }

    /** Active mitigation executions for this twin */
    private _activeMitigations: import("@models/mitigation").MitigationExecution[] = [];
    public get activeMitigations(): import("@models/mitigation").MitigationExecution[] {
        return this._activeMitigations;
    }

    public setActiveMitigations(mitigations: import("@models/mitigation").MitigationExecution[]): void {
        this._activeMitigations = mitigations;
    }

    /** Incident snapshot for presentation */
    private _latestIncidentId: string | null = null;
    public get latestIncidentId(): string | null {
        return this._latestIncidentId;
    }

    private _latestIncidentStatus: import("@models/incident").IncidentStatus | null = null;
    public get latestIncidentStatus(): import("@models/incident").IncidentStatus | null {
        return this._latestIncidentStatus;
    }

    public setLatestIncident(id: string | null, status: import("@models/incident").IncidentStatus | null): void {
        this._latestIncidentId = id;
        this._latestIncidentStatus = status;
    }

    /** Attack overrides mapped by attack execution ID */
    private _attackOverrides: Map<string, Partial<TwinTelemetry>> = new Map();

    /** Timestamp when this twin was created */
    public readonly createdAt: Date;

    /** Timestamp of the last telemetry/state update */
    private _lastUpdate: Date;
    public get lastUpdate(): Date {
        return this._lastUpdate;
    }

    /** Baseline telemetry profile for controlled simulation */
    private readonly _baseline: TelemetryBaseline;

    /** Packet counter — incremented externally, reset each telemetry tick */
    private _packetCount: number = 0;

    /** Bytes counter — incremented externally, reset each telemetry tick */
    private _bytesCount: number = 0;

    /**
     * Creates a new DigitalTwin.
     *
     * @param nodeMac MAC address of the associated node
     * @param deviceType Type of the device
     * @param ip Optional initial IP address
     */
    constructor(nodeMac: string, deviceType: NodeType, ip?: string) {
        this.id = generateTwinId();
        this.nodeMac = nodeMac;
        this.deviceType = deviceType;
        this._ip = ip;
        this._state = DeviceSecurityState.ONLINE;
        this._baseline = getBaselineForType(deviceType);
        this._currentAttackId = null;
        this.createdAt = new Date();
        this._lastUpdate = new Date();

        // Initialize telemetry at baseline values
        this._telemetry = createTelemetry({
            cpuUtilization: this._baseline.cpuBase,
            memoryUtilization: this._baseline.memBase,
            temperature: this._baseline.tempBase,
            batteryLevel: this._baseline.batteryBase,
            sensorReading: this._baseline.sensorBase,
            packetsPerSecond: 0,
            bandwidthUsage: 0,
            latency: 0,
            packetLoss: 0,
            connectionCount: 0,
            authFailures: 0,
        });
    }

    /**
     * Attempts to transition the twin to a new security state.
     * Returns true if the transition was valid, false otherwise.
     *
     * @param newState The target state
     * @returns Whether the transition succeeded
     */
    public transitionTo(newState: DeviceSecurityState): boolean {
        if (!isValidTransition(this._state, newState)) {
            return false;
        }
        this._state = newState;
        this._lastUpdate = new Date();
        return true;
    }

    /**
     * Sets the current attack reference ID.
     *
     * @param attackId The attack execution ID, or null to clear
     */
    public setCurrentAttack(attackId: string | null): void {
        this._currentAttackId = attackId;
        this._lastUpdate = new Date();
    }

    /**
     * Records a packet for traffic metrics.
     * Called by the network layer when traffic passes through this device.
     *
     * @param bytes Size of the packet in bytes
     */
    public recordPacket(bytes: number): void {
        this._packetCount++;
        this._bytesCount += Math.max(0, bytes);
    }

    /**
     * Updates the twin's IP address (called when the node's IP changes).
     */
    public updateIp(ip: string | undefined): void {
        this._ip = ip;
    }

    /**
     * Performs a telemetry update tick.
     * Called periodically by the DigitalTwinService.
     *
     * @param intervalSeconds The telemetry loop interval in seconds
     * @param connectionLatency Latency from the node's active connection (ms), or 0
     * @param connectionCount Number of active connections for this node
     * @param isConnected Whether the node is currently connected to the network
     */
    public updateTelemetry(
        intervalSeconds: number,
        connectionLatency: number,
        connectionCount: number,
        isConnected: boolean,
    ): void {
        const prev = this._telemetry;
        const base = this._baseline;

        // Derive traffic metrics from actual recorded packets
        const pps = intervalSeconds > 0 ? this._packetCount / intervalSeconds : 0;
        const bps = intervalSeconds > 0 ? this._bytesCount / intervalSeconds : 0;

        // CPU: drift near baseline, but increases with traffic load
        const trafficCpuBoost = Math.min(pps * 0.5, 30); // Up to 30% from traffic
        const cpuTarget = base.cpuBase + trafficCpuBoost;
        const cpu = applyDrift(prev.cpuUtilization, cpuTarget, base.cpuDrift, 0, 100);

        // Memory: drift near baseline, slight increase with connections
        const memTarget = base.memBase + connectionCount * 0.5;
        const mem = applyDrift(prev.memoryUtilization, memTarget, base.memDrift, 0, 100);

        // Temperature: correlates with CPU
        const tempTarget = base.tempBase + (cpu - base.cpuBase) * 0.15;
        const temp = applyDrift(prev.temperature, tempTarget, base.tempDrift, 0, 120);

        // Battery: slow drain for IoT, stays at 100 for powered devices
        const battery = base.batteryDrain > 0
            ? clampTelemetry(prev.batteryLevel - base.batteryDrain * intervalSeconds, 0, 100)
            : prev.batteryLevel;

        // Sensor: drift near baseline
        const sensor = base.sensorDrift > 0
            ? applyDrift(prev.sensorReading, base.sensorBase, base.sensorDrift, -1000, 1000)
            : prev.sensorReading;

        // Packet loss: normally near 0, but can drift under heavy load
        const lossTarget = pps > 50 ? Math.min((pps - 50) * 0.2, 15) : 0;
        const loss = applyDrift(prev.packetLoss, lossTarget, 0.5, 0, 100);

        let rawTelemetry: Partial<TwinTelemetry> = {
            cpuUtilization: cpu,
            memoryUtilization: mem,
            packetsPerSecond: pps,
            bandwidthUsage: bps,
            latency: connectionLatency,
            packetLoss: isConnected ? loss : 0,
            connectionCount: connectionCount,
            temperature: temp,
            batteryLevel: battery,
            authFailures: prev.authFailures,
            sensorReading: sensor,
        };

        // Apply active overrides
        for (const override of this._attackOverrides.values()) {
            rawTelemetry = { ...rawTelemetry, ...override };
        }

        this._telemetry = createTelemetry(rawTelemetry);

        // Reset per-tick counters
        this._packetCount = 0;
        this._bytesCount = 0;
        this._lastUpdate = new Date();
    }

    /**
     * Increments the authentication failure counter.
     */
    public recordAuthFailure(): void {
        // Recreate telemetry with incremented authFailures
        this._telemetry = createTelemetry({
            ...this._telemetry,
            authFailures: this._telemetry.authFailures + 1,
        });
    }

    public resetAuthFailures(): void {
        this._telemetry = createTelemetry({
            ...this._telemetry,
            authFailures: 0,
        });
    }

    /**
     * Applies a temporary telemetry override associated with an attack.
     * Overrides are merged into the telemetry on every tick until cleared.
     *
     * @param overrides Partial telemetry to spoof
     * @param attackId Unique ID of the attack owning this override
     */
    public applyAttackOverrides(overrides: Partial<TwinTelemetry>, attackId: string): void {
        this._attackOverrides.set(attackId, overrides);
        this._lastUpdate = new Date();
    }

    /**
     * Clears a temporary telemetry override.
     *
     * @param attackId Unique ID of the attack owning this override
     */
    public clearAttackOverrides(attackId: string): void {
        this._attackOverrides.delete(attackId);
        this._lastUpdate = new Date();
    }

    /** Removes telemetry overrides whose owning attacks are no longer active. */
    public retainAttackOverrides(activeAttackIds: ReadonlySet<string>): void {
        for (const attackId of this._attackOverrides.keys()) {
            if (!activeAttackIds.has(attackId)) {
                this._attackOverrides.delete(attackId);
            }
        }
    }
}
