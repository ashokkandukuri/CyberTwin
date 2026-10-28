/**
 * Enum representing the operational/security state of a device's Digital Twin.
 */
export enum DeviceSecurityState {
    ONLINE = "online",
    OFFLINE = "offline",
    DEGRADED = "degraded",
    SUSPICIOUS = "suspicious",
    UNDER_ATTACK = "under_attack",
    COMPROMISED = "compromised",
    RECOVERING = "recovering",
    RECOVERED = "recovered",
}

/**
 * Valid state transitions. Each key maps to the set of states
 * that are reachable from that state.
 */
const VALID_TRANSITIONS: ReadonlyMap<DeviceSecurityState, ReadonlySet<DeviceSecurityState>> = new Map<DeviceSecurityState, Set<DeviceSecurityState>>([
    [DeviceSecurityState.ONLINE, new Set<DeviceSecurityState>([
        DeviceSecurityState.OFFLINE,
        DeviceSecurityState.DEGRADED,
        DeviceSecurityState.SUSPICIOUS,
        DeviceSecurityState.UNDER_ATTACK,
    ])],
    [DeviceSecurityState.OFFLINE, new Set<DeviceSecurityState>([
        DeviceSecurityState.ONLINE,
    ])],
    [DeviceSecurityState.DEGRADED, new Set<DeviceSecurityState>([
        DeviceSecurityState.ONLINE,
        DeviceSecurityState.SUSPICIOUS,
        DeviceSecurityState.UNDER_ATTACK,
        DeviceSecurityState.OFFLINE,
    ])],
    [DeviceSecurityState.SUSPICIOUS, new Set<DeviceSecurityState>([
        DeviceSecurityState.ONLINE,
        DeviceSecurityState.DEGRADED,
        DeviceSecurityState.UNDER_ATTACK,
        DeviceSecurityState.COMPROMISED,
        DeviceSecurityState.RECOVERING,
        DeviceSecurityState.OFFLINE,
    ])],
    [DeviceSecurityState.UNDER_ATTACK, new Set<DeviceSecurityState>([
        DeviceSecurityState.COMPROMISED,
        DeviceSecurityState.RECOVERING,
        DeviceSecurityState.OFFLINE,
    ])],
    [DeviceSecurityState.COMPROMISED, new Set<DeviceSecurityState>([
        DeviceSecurityState.RECOVERING,
        DeviceSecurityState.OFFLINE,
    ])],
    [DeviceSecurityState.RECOVERING, new Set<DeviceSecurityState>([
        DeviceSecurityState.RECOVERED,
        DeviceSecurityState.COMPROMISED,
        DeviceSecurityState.OFFLINE,
    ])],
    [DeviceSecurityState.RECOVERED, new Set<DeviceSecurityState>([
        DeviceSecurityState.ONLINE,
        DeviceSecurityState.OFFLINE,
    ])],
]);

/**
 * Checks whether a transition from `from` to `to` is valid.
 *
 * @param from Current state
 * @param to Target state
 * @returns true if the transition is allowed
 */
export function isValidTransition(from: DeviceSecurityState, to: DeviceSecurityState): boolean {
    if (from === to) return true; // Identity transition is always valid
    const allowed = VALID_TRANSITIONS.get(from);
    return allowed !== undefined && allowed.has(to);
}

/**
 * Returns a human-readable label for a DeviceSecurityState.
 *
 * @param state The state to convert
 * @returns i18n-compatible label key
 */
export function stateToLabel(state: DeviceSecurityState): string {
    switch (state) {
        case DeviceSecurityState.ONLINE:       return "STATE_ONLINE";
        case DeviceSecurityState.OFFLINE:      return "STATE_OFFLINE";
        case DeviceSecurityState.DEGRADED:     return "STATE_DEGRADED";
        case DeviceSecurityState.SUSPICIOUS:   return "STATE_SUSPICIOUS";
        case DeviceSecurityState.UNDER_ATTACK: return "STATE_UNDER_ATTACK";
        case DeviceSecurityState.COMPROMISED:  return "STATE_COMPROMISED";
        case DeviceSecurityState.RECOVERING:   return "STATE_RECOVERING";
        case DeviceSecurityState.RECOVERED:    return "STATE_RECOVERED";
    }
}

/**
 * Returns a severity level (0–3) for a DeviceSecurityState.
 * 0 = normal, 1 = warning, 2 = danger, 3 = critical
 */
export function stateSeverityLevel(state: DeviceSecurityState): number {
    switch (state) {
        case DeviceSecurityState.ONLINE:
        case DeviceSecurityState.RECOVERED:
            return 0;
        case DeviceSecurityState.OFFLINE:
        case DeviceSecurityState.DEGRADED:
            return 1;
        case DeviceSecurityState.SUSPICIOUS:
        case DeviceSecurityState.RECOVERING:
            return 2;
        case DeviceSecurityState.UNDER_ATTACK:
        case DeviceSecurityState.COMPROMISED:
            return 3;
    }
}
