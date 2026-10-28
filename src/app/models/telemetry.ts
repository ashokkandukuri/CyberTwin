import { NodeType } from "@models/node";

/**
 * Represents a snapshot of simulated telemetry data for a Digital Twin.
 * All numeric values are clamped to valid ranges.
 */
export interface TwinTelemetry {
    /** CPU utilization in percent (0–100) */
    readonly cpuUtilization: number;
    /** Memory utilization in percent (0–100) */
    readonly memoryUtilization: number;
    /** Packets per second (>= 0), derived from actual traffic when possible */
    readonly packetsPerSecond: number;
    /** Bandwidth usage in bytes/sec (>= 0) */
    readonly bandwidthUsage: number;
    /** Latency in milliseconds (>= 0), derived from connection model */
    readonly latency: number;
    /** Packet loss in percent (0–100) */
    readonly packetLoss: number;
    /** Number of active connections (>= 0) */
    readonly connectionCount: number;
    /** Simulated device temperature in °C (0–120) */
    readonly temperature: number;
    /** Simulated battery level in percent (0–100) */
    readonly batteryLevel: number;
    /** Count of authentication failures since last reset (>= 0) */
    readonly authFailures: number;
    /** Device-specific sensor reading value */
    readonly sensorReading: number;
}

/**
 * Clamps a number to a [min, max] range and guards against NaN/Infinity.
 *
 * @param value The value to clamp
 * @param min Minimum allowed value
 * @param max Maximum allowed value
 * @returns A finite number within [min, max]
 */
export function clampTelemetry(value: number, min: number, max: number): number {
    if (!Number.isFinite(value)) return min;
    return Math.min(Math.max(value, min), max);
}

/**
 * Creates a sanitized TwinTelemetry snapshot with all values clamped to valid ranges.
 *
 * @param raw Partial or complete telemetry data
 * @returns A fully validated TwinTelemetry
 */
export function createTelemetry(raw: Partial<TwinTelemetry>): TwinTelemetry {
    return Object.freeze({
        cpuUtilization:    clampTelemetry(raw.cpuUtilization    ?? 0, 0, 100),
        memoryUtilization: clampTelemetry(raw.memoryUtilization ?? 0, 0, 100),
        packetsPerSecond:  clampTelemetry(raw.packetsPerSecond  ?? 0, 0, Number.MAX_SAFE_INTEGER),
        bandwidthUsage:    clampTelemetry(raw.bandwidthUsage    ?? 0, 0, Number.MAX_SAFE_INTEGER),
        latency:           clampTelemetry(raw.latency           ?? 0, 0, Number.MAX_SAFE_INTEGER),
        packetLoss:        clampTelemetry(raw.packetLoss        ?? 0, 0, 100),
        connectionCount:   clampTelemetry(raw.connectionCount   ?? 0, 0, Number.MAX_SAFE_INTEGER),
        temperature:       clampTelemetry(raw.temperature       ?? 25, 0, 120),
        batteryLevel:      clampTelemetry(raw.batteryLevel      ?? 100, 0, 100),
        authFailures:      clampTelemetry(raw.authFailures      ?? 0, 0, Number.MAX_SAFE_INTEGER),
        sensorReading:     clampTelemetry(raw.sensorReading     ?? 0, -Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER),
    });
}

/**
 * Baseline telemetry profiles per device type.
 * These provide realistic starting values that drift gradually.
 */
export interface TelemetryBaseline {
    readonly cpuBase: number;
    readonly cpuDrift: number;
    readonly memBase: number;
    readonly memDrift: number;
    readonly tempBase: number;
    readonly tempDrift: number;
    readonly batteryBase: number;
    readonly batteryDrain: number;
    readonly sensorBase: number;
    readonly sensorDrift: number;
}

/**
 * Returns the baseline telemetry profile for a given node type.
 */
export function getBaselineForType(type: NodeType): TelemetryBaseline {
    switch (type) {
        case NodeType.ROUTER:
            return {
                cpuBase: 20, cpuDrift: 3,
                memBase: 45, memDrift: 2,
                tempBase: 42, tempDrift: 1.5,
                batteryBase: 100, batteryDrain: 0, // Routers typically have power supply
                sensorBase: 0, sensorDrift: 0,
            };
        case NodeType.IOT:
            return {
                cpuBase: 12, cpuDrift: 4,
                memBase: 35, memDrift: 3,
                tempBase: 38, tempDrift: 2,
                batteryBase: 85, batteryDrain: 0.02, // IoT devices drain battery slowly
                sensorBase: 22, sensorDrift: 1.5, // e.g. temperature sensor
            };
        case NodeType.COMPUTER:
            return {
                cpuBase: 25, cpuDrift: 5,
                memBase: 55, memDrift: 4,
                tempBase: 45, tempDrift: 2,
                batteryBase: 100, batteryDrain: 0,
                sensorBase: 0, sensorDrift: 0,
            };
    }
}

/**
 * Applies a small, controlled drift to a value, clamping within bounds.
 * Uses a simple random walk that keeps values near their baseline.
 *
 * @param current Current value
 * @param baseline Target baseline to drift toward
 * @param maxDrift Maximum per-tick drift amount
 * @param min Minimum allowed value
 * @param max Maximum allowed value
 * @returns New value after drift
 */
export function applyDrift(
    current: number,
    baseline: number,
    maxDrift: number,
    min: number,
    max: number,
): number {
    // Bias toward baseline: if current > baseline, more likely to drift down
    const pull = (baseline - current) * 0.1;
    const noise = (Math.random() - 0.5) * 2 * maxDrift;
    const next = current + pull + noise;
    return clampTelemetry(next, min, max);
}
