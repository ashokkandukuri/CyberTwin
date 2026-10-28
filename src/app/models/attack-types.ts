/**
 * Types of attacks supported by the Attack Engine.
 */
export enum AttackType {
    DOS = "dos",
    MQTT_FLOOD = "mqtt_flood",
    SENSOR_SPOOF = "sensor_spoof",
    BRUTE_FORCE = "brute_force",
    PORT_SCAN = "port_scan",
}

/** Resource Limits & Constants */
export const MAX_ATTACK_DURATION_MS = 300000;     // 5 minutes
export const MIN_ATTACK_DURATION_MS = 1000;       // 1 second
export const MAX_INTENSITY = 10;
export const MIN_INTENSITY = 1;
export const MAX_ACTIVE_ATTACKS = 3;
export const MAX_SIMULATED_EVENTS_PER_ATTACK = 10000;
export const ATTACK_TICK_INTERVAL_MS = 200;       // 200ms per tick
export const MAX_MQTT_PAYLOAD_SIZE = 256000;      // 256 KB
export const MAX_PORT_SCAN_RANGE = 256;           // Max ports to scan per attack

/**
 * Type-specific parameters for each attack type.
 */
export interface DosParameters {
    readonly dstPort: number;
    readonly ttlRange: [number, number];
}

export interface MqttFloodParameters {
    readonly topic: string;
    readonly payloadSizeBytes: number;
}

export interface SensorSpoofParameters {
    readonly targetField: string;
    readonly spoofValue: number;
}

export interface BruteForceParameters {
    readonly targetService: string;
}

export interface PortScanParameters {
    readonly portRange: [number, number];
}

export type AttackParameters =
    | DosParameters
    | MqttFloodParameters
    | SensorSpoofParameters
    | BruteForceParameters
    | PortScanParameters;

/**
 * Configuration required to launch an attack.
 */
export interface AttackConfig {
    readonly type: AttackType;
    readonly targetNodeMac: string;
    readonly sourceNodeMac: string;
    readonly durationMs: number;       // Must be between MIN_ATTACK_DURATION_MS and MAX_ATTACK_DURATION_MS
    readonly intensity: number;        // Must be between MIN_INTENSITY and MAX_INTENSITY
    readonly parameters: AttackParameters;
}
