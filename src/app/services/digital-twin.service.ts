import {
    Injectable,
    OnDestroy,
    signal,
    computed,
    Signal,
    WritableSignal,
} from "@angular/core";
import { DigitalTwin } from "@models/digital-twin";
import { DeviceSecurityState } from "@models/device-state";
import { Node, NodeType } from "@models/node";
import { Router } from "@models/router";
import {
    SecurityEventType,
    SecurityEventSeverity,
} from "@models/security-event";
import { SecurityEventService } from "@services/security-event.service";
import { AnomalyDetectionService } from "@services/anomaly-detection.service";
import { AnomalySeverity, AnomalyResult } from "@models/anomaly";
import { RiskScoringService } from "@services/risk-scoring.service";
import { AttackEngineService } from "@services/attack-engine.service";
import { AttackType, SensorSpoofParameters, BruteForceParameters } from "@models/attack-types";
import { AttackExecution, AttackStatus } from "@models/attack-execution";
import { RiskLevel, RiskAssessment } from "@models/risk";
import { ImpactAnalysisService } from "@services/impact-analysis.service";
import { ImpactLevel, ImpactAssessment } from "@models/impact";
import { MitigationPolicyService } from "@services/mitigation-policy.service";
import { MitigationEngineService } from "@services/mitigation-engine.service";
import { RecoveryService, RecoveryTransition } from "@services/recovery.service";
import { MitigationExecution, MitigationStatus, MitigationType } from "@models/mitigation";
import { IncidentStatus } from "@models/incident";
import { IncidentCorrelationService } from "@services/incident-correlation.service";
import { NetworkService } from "@services/network.service";
import { Subscription } from "rxjs";
import { randomInt } from "@utils/random";

/** Telemetry update interval in milliseconds */
const TELEMETRY_INTERVAL_MS = 2000;

/**
 * Keep the most recently completed attack available to the mitigation policy
 * for a short post-attack window. This covers the normal simulation case where
 * operational impact becomes visible on the telemetry tick immediately after
 * the attack lifecycle has completed.
 */
const POST_ATTACK_MITIGATION_TICKS = 3;

interface IncidentDemoLifecycle {
    readonly twinId: string;
    readonly mitigationDueAt: number;
    readonly expiresAt: number;
    mitigationApplied: boolean;
    recoveryDueAt?: number;
    recoveryStarted: boolean;
}

const INCIDENT_MITIGATION_DELAY_MIN_MS = 2000;
const INCIDENT_MITIGATION_DELAY_MAX_MS = 5000;
const INCIDENT_RECOVERY_DELAY_MIN_MS = 3000;
const INCIDENT_RECOVERY_DELAY_MAX_MS = 6000;

/**
 * Service responsible for managing Digital Twins of all network nodes.
 *
 * Responsibilities:
 * - Create/remove Digital Twins when nodes are added/removed
 * - Run a periodic telemetry update loop
 * - Expose twin state reactively via Angular signals
 * - Derive telemetry from actual network state (latency, connections, traffic)
 *
 * This service does NOT hold direct references to Angular components.
 * It communicates with the simulation layer through the NetworkService.
 */
@Injectable({ providedIn: "root" })
export class DigitalTwinService implements OnDestroy {
    /** Internal map of twins by node MAC address */
    private readonly _twins: Map<string, DigitalTwin> = new Map();

    /** Anomaly state tracking for debouncing and hysteresis */
    private readonly _anomalyStates = new Map<string, { severity: AnomalySeverity, clearStreak: number }>();

    /** Phase 4: Risk persistence tracking (consecutive anomalous ticks) */
    private readonly _riskPersistenceStates = new Map<string, number>();

    /** Phase 4: Risk event debounce tracking */
    private readonly _riskDebounceStates = new Map<string, { lastEmittedLevel: RiskLevel | null, candidateLevel: RiskLevel | null, consecutiveTicks: number }>();

    /** Phase 5: Impact event debounce tracking */
    private readonly _impactDebounceStates = new Map<string, { lastEmittedLevel: ImpactLevel | null, candidateLevel: ImpactLevel | null, consecutiveTicks: number }>();

    /** Last observed Node.traffic length per MAC, used to derive per-tick traffic telemetry. */
    private readonly _trafficSnapshots = new Map<string, number>();

    /**
     * Recent attack context retained briefly after completion so delayed impact
     * can still trigger a mitigation recommendation for the attack that caused it.
     */
    private readonly _recentAttackContexts = new Map<string, { execution: AttackExecution; remainingTicks: number }>();

    /** Per-execution demonstration lifecycle, advanced by the existing telemetry loop. */
    private readonly _incidentDemoLifecycles = new Map<string, IncidentDemoLifecycle>();

    /** Signal that increments on every twin change (creation, removal, update) */
    private readonly _revision: WritableSignal<number> = signal(0);

    /** Telemetry loop interval handle */
    private _intervalHandle: ReturnType<typeof setInterval> | null = null;

    /** Reference to the network's nodes getter (set during integration) */
    private _getNodes: (() => Node[]) | null = null;

    /** Reference to the network's router getter */
    private _getRouter: (() => Router | undefined) | null = null;

    /** Subscriptions for network events */
    private _networkSubs = new Subscription();

    /** Reactive snapshot of all twins as an array */
    public readonly twins: Signal<readonly DigitalTwin[]> = computed(() => {
        // Touch revision to trigger reactivity on twin changes
        this._revision();
        return [...this._twins.values()];
    });

    /** Number of active twins */
    public readonly twinCount: Signal<number> = computed(() => this.twins().length);

    constructor(
        private readonly securityEvents: SecurityEventService,
        private readonly anomalyDetection: AnomalyDetectionService,
        private readonly riskScoring: RiskScoringService,
        private readonly attackEngine: AttackEngineService,
        private readonly impactAnalysis: ImpactAnalysisService,
        private readonly mitigationPolicy: MitigationPolicyService,
        private readonly mitigationEngine: MitigationEngineService,
        private readonly recoveryService: RecoveryService,
        private readonly incidentCorrelation: IncidentCorrelationService,
        private readonly networkService: NetworkService
    ) {
        this._getNodes = () => this.networkService.nodes;
        this._getRouter = () => this.networkService.router;
        
        this._networkSubs.add(this.networkService.onNetworkReset.subscribe(() => {
            this.reset();
            this.syncWithNetwork();
        }));
        
        this._networkSubs.add(this.networkService.onNodeAdded.subscribe((node) => {
            this.createTwin(node);
        }));
        
        this._networkSubs.add(this.networkService.onNodeRemoved.subscribe((mac) => {
            this.removeTwin(mac);
        }));

        // The NetworkService can restore the current network from sessionStorage
        // before DigitalTwinService is first instantiated. In that case the
        // onNodeAdded/onNetworkReset events have already happened, so an initial
        // synchronization is required to create twins for the existing nodes.
        this.syncWithNetwork();

        this._startTelemetryLoop();
    }

    /**
     * Legacy initialize method. Now a no-op as initialization happens in constructor.
     * Kept for backwards compatibility.
     *
     * @param getNodes Function that returns current network nodes
     * @param getRouter Function that returns the current router (if any)
     */
    public initialize(
        getNodes: () => Node[],
        getRouter: () => Router | undefined,
    ): void {
        // No-op
    }

    /**
     * Creates a Digital Twin for a node.
     *
     * @param node The node to create a twin for
     * @returns The created DigitalTwin, or undefined if one already exists
     */
    public createTwin(node: Node): DigitalTwin | undefined {
        if (this._twins.has(node.mac)) {
            return this._twins.get(node.mac);
        }

        const twin = new DigitalTwin(node.mac, node.type, node.ip);
        this._twins.set(node.mac, twin);
        this._notifyChange();

        // Emit security event
        this.securityEvents.emit({
            type: SecurityEventType.TWIN_CREATED,
            severity: SecurityEventSeverity.INFO,
            source: node.mac,
            description: `Digital Twin created for ${node.name} (${node.type})`,
            metadata: { deviceType: node.type, twinId: twin.id },
        });

        return twin;
    }

    /**
     * Removes the Digital Twin for a node.
     *
     * @param mac MAC address of the node
     * @returns true if a twin was found and removed
     */
    public removeTwin(mac: string): boolean {
        const twin = this._twins.get(mac);
        if (!twin) return false;

        this._twins.delete(mac);
        this._anomalyStates.delete(twin.id);
        this._riskPersistenceStates.delete(twin.id);
        this._riskDebounceStates.delete(twin.id);
        this._impactDebounceStates.delete(twin.id);
        this._trafficSnapshots.delete(mac);
        this._recentAttackContexts.delete(twin.id);
        for (const [attackId, lifecycle] of this._incidentDemoLifecycles) {
            if (lifecycle.twinId === twin.id) this._incidentDemoLifecycles.delete(attackId);
        }
        this.anomalyDetection.cleanupTwin(twin.id);
        this.mitigationEngine.cleanupForTwin(twin.id);
        this.recoveryService.cleanupForTwin(twin.id);
        this._notifyChange();

        // Emit security event
        this.securityEvents.emit({
            type: SecurityEventType.TWIN_REMOVED,
            severity: SecurityEventSeverity.INFO,
            source: mac,
            description: `Digital Twin removed for device ${mac}`,
            metadata: { twinId: twin.id },
        });

        return true;
    }

    /**
     * Retrieves a Digital Twin by node MAC address.
     *
     * @param mac MAC address of the node
     * @returns The DigitalTwin, or undefined if not found
     */
    public getTwin(mac: string): DigitalTwin | undefined {
        return this._twins.get(mac);
    }

    /**
     * Transitions a twin's security state, with validation.
     *
     * @param mac MAC address of the node
     * @param newState The target security state
     * @returns true if the transition was valid and applied
     */
    public transitionState(mac: string, newState: DeviceSecurityState): boolean {
        const twin = this._twins.get(mac);
        if (!twin) return false;

        const oldState = twin.state;
        const success = twin.transitionTo(newState);

        if (success && oldState !== newState) {
            this._notifyChange();

            this.securityEvents.emit({
                type: SecurityEventType.STATE_CHANGED,
                severity: this._severityForStateChange(newState),
                source: mac,
                description: `Device state changed: ${oldState} → ${newState}`,
                metadata: { previousState: oldState, newState: newState, twinId: twin.id },
            });
        }

        return success;
    }

    /**
     * Removes all twins and stops the telemetry loop.
     * Used when creating a new network.
     */
    public reset(): void {
        for (const twin of this._twins.values()) {
            this.anomalyDetection.cleanupTwin(twin.id);
        }
        this._twins.clear();
        this._anomalyStates.clear();
        this._riskPersistenceStates.clear();
        this._riskDebounceStates.clear();
        this._impactDebounceStates.clear();
        this._trafficSnapshots.clear();
        this._recentAttackContexts.clear();
        this._incidentDemoLifecycles.clear();
        this.mitigationEngine.reset();
        this.recoveryService.reset();
        this._notifyChange();
    }

    /**
     * Synchronizes twins with the current network state.
     * Creates twins for nodes that don't have one, removes twins for nodes
     * that no longer exist. Called after network load/reset.
     */
    public syncWithNetwork(): void {
        if (!this._getNodes) return;

        const nodes = this._getNodes();
        const currentMacs = new Set(nodes.map(n => n.mac));

        // Remove twins for nodes that no longer exist
        for (const mac of this._twins.keys()) {
            if (!currentMacs.has(mac)) {
                this.removeTwin(mac);
            }
        }

        // Create twins for nodes that don't have one
        for (const node of nodes) {
            if (!this._twins.has(node.mac)) {
                this.createTwin(node);
            }
        }
    }

    /**
     * Starts the periodic telemetry update loop.
     */
    private _startTelemetryLoop(): void {
        if (this._intervalHandle !== null) return;

        this._intervalHandle = setInterval(() => {
            this._updateAllTelemetry();
        }, TELEMETRY_INTERVAL_MS);
    }

    /**
     * Stops the telemetry update loop.
     */
    private _stopTelemetryLoop(): void {
        if (this._intervalHandle !== null) {
            clearInterval(this._intervalHandle);
            this._intervalHandle = null;
        }
    }

    /**
     * Updates telemetry for all active twins, deriving values from the
     * actual network simulation state where possible.
     */
    private _updateAllTelemetry(): void {
        if (!this._getNodes || !this._getRouter) return;

        const router = this._getRouter();
        const intervalSeconds = TELEMETRY_INTERVAL_MS / 1000;
        const activeAttacksForNetwork = this.attackEngine.activeAttacks();

        for (const [mac, twin] of this._twins.entries()) {
            // Find the corresponding node
            const nodes = this._getNodes();
            const node = nodes.find(n => n.mac === mac);

            if (!node) continue;

            // Update IP from live node
            twin.updateIp(node.ip);

            // Derive connection metrics from router's connection table
            let connectionLatency = 0;
            let connectionCount = 0;

            if (router && NodeType.RouterTypes.includes(node.type)) {
                // Router itself: count all connections
                connectionCount = router.connections.length;
                // Average latency across all connections
                if (connectionCount > 0) {
                    const totalLatency = router.connections.reduce(
                        (sum, c) => sum + c.latency, 0,
                    );
                    connectionLatency = totalLatency / connectionCount;
                }
            } else if (router) {
                // Device: find its connection from the router
                const conn = router.connections.find(
                    c => c.node2.mac === mac || c.node1.mac === mac,
                );
                if (conn) {
                    connectionLatency = conn.latency;
                    connectionCount = 1;
                }
            }

            const isConnected = node.connected;
            const activeAttacksForTwin = activeAttacksForNetwork.filter(
                execution => execution.config.targetNodeMac === twin.nodeMac,
            );
            twin.retainAttackOverrides(
                new Set(activeAttacksForTwin.map(execution => execution.id)),
            );

            // Derive per-tick traffic from the Node traffic history.
            // The legacy DigitalTwin counters are reset every tick, but the network
            // model records packets on each Node. Keeping the delta here makes the
            // telemetry reflect the simulated traffic actually visible in Network Traffic.
            const currentTraffic = node.traffic;
            const previousTrafficLength = this._trafficSnapshots.get(mac) ?? currentTraffic.length;
            const startIndex = Math.min(previousTrafficLength, currentTraffic.length);
            const trafficPacketCount = Math.max(0, currentTraffic.length - previousTrafficLength);
            let trafficBytes = 0;
            for (let i = startIndex; i < currentTraffic.length; i++) {
                const bytes = currentTraffic[i]?.totalBytes;
                if (typeof bytes === "number" && Number.isFinite(bytes)) {
                    trafficBytes += Math.max(0, bytes);
                }
            }
            this._trafficSnapshots.set(mac, currentTraffic.length);

            for (let i = 0; i < trafficPacketCount; i++) {
                // Keep the DigitalTwin's existing per-tick counters as the telemetry source.
                // We add one packet at a time so both packet and byte accounting stay consistent.
                const bytes = currentTraffic[startIndex + i]?.totalBytes ?? 0;
                twin.recordPacket(bytes);
            }

            // Update the twin's baseline telemetry first.
            twin.updateTelemetry(
                intervalSeconds,
                connectionLatency,
                connectionCount,
                isConnected,
            );

            // Apply deterministic, target-side effects for active simulated attacks
            // before detection/risk/impact evaluation. The network model records real
            // simulated packets, but a Digital Twin also needs a bounded operational
            // effect so DoS/MQTT attacks can exercise the Phase 5 performance path.
            const telemetryAttack = activeAttacksForTwin[0];
            if (telemetryAttack) {
                this._applyAttackTelemetryEffects(twin, telemetryAttack, connectionLatency);
            }

            // Process telemetry through the anomaly detector
            const anomaly = this.anomalyDetection.processTelemetry(twin);
            
            // --- Phase 4 Risk Integration ---
            // 1. Persistence Tracking
            let persistence = this._riskPersistenceStates.get(twin.id) || 0;
            if (anomaly.severity !== AnomalySeverity.NORMAL) {
                persistence++;
            } else {
                persistence = 0;
            }
            this._riskPersistenceStates.set(twin.id, persistence);

            // 2. Resolve Attack Execution (if any)
            let activeAttack = activeAttacksForNetwork.find(e => e.config.targetNodeMac === twin.nodeMac) || null;

            // Retain the most recent attack briefly after it completes. Impact is
            // calculated from telemetry, so the first MEDIUM/HIGH impact transition
            // can legitimately arrive one or more telemetry ticks after the attack
            // lifecycle has ended. The retained execution is used only for policy
            // correlation; recovery still considers whether the attack is actually active.
            if (activeAttack) {
                this._recentAttackContexts.set(twin.id, {
                    execution: activeAttack,
                    remainingTicks: POST_ATTACK_MITIGATION_TICKS
                });
                if (twin.currentAttackId !== activeAttack.id) {
                    twin.setCurrentAttack(activeAttack.id);
                    if (activeAttack.config.type === AttackType.SENSOR_SPOOF || activeAttack.config.type === AttackType.BRUTE_FORCE || activeAttack.config.type === AttackType.PORT_SCAN) {
                        twin.transitionTo(DeviceSecurityState.SUSPICIOUS);
                    } else {
                        twin.transitionTo(DeviceSecurityState.UNDER_ATTACK);
                    }
                }
                
                // Attack effects
                if (activeAttack.config.type === AttackType.SENSOR_SPOOF) {
                    const params = activeAttack.config.parameters as SensorSpoofParameters;
                    const isSuppressed = this.mitigationEngine.isSensorSpoofSuppressed(activeAttack.id);
                    if (!isSuppressed) {
                        twin.applyAttackOverrides({ [params.targetField]: params.spoofValue }, activeAttack.id);
                    } else {
                        twin.clearAttackOverrides(activeAttack.id);
                    }
                }
                
                if (activeAttack.config.type === AttackType.BRUTE_FORCE) {
                    const intensity = activeAttack.config.intensity;
                    // For a 2s interval, attempts = intensity * 2 * (2000 / 300)
                    const attempts = Math.floor(intensity * (TELEMETRY_INTERVAL_MS / 300) * 2);
                    for (let i = 0; i < attempts; i++) {
                        twin.recordAuthFailure();
                    }
                }
            } else {
                if (twin.currentAttackId) {
                    twin.clearAttackOverrides(twin.currentAttackId);
                    twin.setCurrentAttack(null);
                }
            }

            // 3. Calculate Risk Assessment
            const riskAssessment = this.riskScoring.evaluateRisk(twin, anomaly, persistence, activeAttack);
            twin.setLatestRiskAssessment(riskAssessment);

            // 4. State Integration
            this._handleAnomalyResult(twin, anomaly);
            
            // 5. Risk Event Debouncing Policy
            this._handleRiskAssessment(twin, riskAssessment);

            // --- Phase 5 Impact Integration ---
            // 6. Calculate Impact Assessment
            const impactAttack = activeAttack ??
                this._recentAttackContexts.get(twin.id)?.execution ??
                this.attackEngine.getRecentAttackForTarget(
                    twin.nodeMac,
                    POST_ATTACK_MITIGATION_TICKS * TELEMETRY_INTERVAL_MS,
                );
            const impactAssessment = this.impactAnalysis.evaluateImpact(
                twin.id,
                twin.nodeMac,
                twin.telemetry,
                anomaly,
                impactAttack,
            );
            twin.setLatestImpactAssessment(impactAssessment);

            // 7. Impact Event Debouncing Policy
            this._handleImpactAssessment(twin, impactAssessment);

            // --- Phase 6 Mitigation Integration ---
            // 8. Mitigation Policy Evaluation
            // Use active attacks plus a short-lived post-attack context. This allows
            // delayed impact telemetry to trigger the correct mitigation without
            // pretending that a completed attack is still running.
            const activeAttacks = activeAttacksForNetwork;
            const recentAttackContext = this._recentAttackContexts.get(twin.id);
            const mitigationAttacks: AttackExecution[] = [...activeAttacks];

            if (!activeAttack) {
                // Prefer the retained context from a prior telemetry tick. If an attack
                // completed between ticks before being observed as active, recover the
                // same context directly from the attack history instead of losing the
                // mitigation opportunity.
                let delayedAttack = recentAttackContext?.execution;
                if (!delayedAttack || (recentAttackContext?.remainingTicks ?? 0) <= 0) {
                    delayedAttack = this.attackEngine.getRecentAttackForTarget(
                        twin.nodeMac,
                        POST_ATTACK_MITIGATION_TICKS * TELEMETRY_INTERVAL_MS,
                    );
                }

                if (delayedAttack) {
                    if (!mitigationAttacks.some(a => a.id === delayedAttack!.id)) {
                        mitigationAttacks.push(delayedAttack);
                    }
                    if (recentAttackContext) {
                        recentAttackContext.remainingTicks--;
                        if (recentAttackContext.remainingTicks <= 0) {
                            this._recentAttackContexts.delete(twin.id);
                        }
                    }
                }
            }

            const recommendations = this.mitigationPolicy.evaluate(twin.id, impactAssessment, mitigationAttacks);
            
            for (const rec of recommendations) {
                // Apply is idempotent; emit the recommendation only when this exact
                // mitigation does not already exist. This preserves a truthful
                // RECOMMENDED -> APPLIED event order without duplicating evidence.
                const existing = this.mitigationEngine.mitigations.find(m =>
                    m.twinId === rec.twinId &&
                    m.type === rec.mitigationType &&
                    m.relatedAttackId === rec.relatedAttackId &&
                    (m.status === MitigationStatus.APPLIED || m.status === MitigationStatus.VERIFYING)
                );

                if (!existing) {
                    this.securityEvents.emit({
                        type: SecurityEventType.MITIGATION_RECOMMENDED,
                        severity: SecurityEventSeverity.INFO,
                        source: twin.id,
                        relatedAttackId: rec.relatedAttackId,
                        description: `Mitigation recommended: ${rec.mitigationType}`,
                        metadata: {
                            twinId: twin.id,
                            mitigationType: rec.mitigationType,
                            reason: rec.reason,
                            relatedAttackId: rec.relatedAttackId ?? "None"
                        }
                    });
                }

                const execution = this.mitigationEngine.applyMitigation(rec);
                if (execution && !existing) {
                    this.securityEvents.emit({
                        type: SecurityEventType.MITIGATION_APPLIED,
                        severity: SecurityEventSeverity.MEDIUM,
                        source: twin.id,
                        relatedAttackId: execution.relatedAttackId,
                        description: `Mitigation applied: ${rec.mitigationType}`,
                        metadata: {
                            twinId: twin.id,
                            mitigationId: execution.id,
                            mitigationType: rec.mitigationType,
                            relatedAttackId: rec.relatedAttackId ?? "None"
                        }
                    });
                }
            }

            // The incident demo progresses from the same attack/mitigation
            // state already evaluated above. It is advanced on this existing
            // telemetry loop and does not alter Digital Twin recovery gates.
            const demoAttacks = new Map(
                [
                    ...activeAttacksForTwin,
                    ...this.attackEngine.attackHistory().filter(attack =>
                        attack.config.targetNodeMac === twin.nodeMac &&
                        attack.status !== AttackStatus.FAILED &&
                        Date.now() - attack.createdAt.getTime() <= 20_000,
                    ),
                ].map(attack => [attack.id, attack]),
            );
            this._advanceIncidentDemoLifecycle(twin, [...demoAttacks.values()], Date.now());

            // 9. Sync twin's active mitigations with engine's source of truth
            const allActiveMitigations = this.mitigationEngine.mitigations.filter(m => m.twinId === twin.id);
            twin.setActiveMitigations(allActiveMitigations);

            // A mitigation-specific recovery loop cannot run when policy did not
            // create a mitigation. Keep the same attack-inactive, NORMAL anomaly,
            // LOW impact, five-consecutive-tick gate for those attack lifecycles.
            const hasActiveMitigation = allActiveMitigations.some(m =>
                m.status === MitigationStatus.APPLIED || m.status === MitigationStatus.VERIFYING
            );
            const needsTwinRecovery = [
                DeviceSecurityState.UNDER_ATTACK,
                DeviceSecurityState.SUSPICIOUS,
                DeviceSecurityState.COMPROMISED,
                DeviceSecurityState.RECOVERING,
            ].includes(twin.state);

            if (!hasActiveMitigation && needsTwinRecovery) {
                const relevantAttackActive = activeAttacks.some(a => a.config.targetNodeMac === twin.nodeMac);
                const transition = this.recoveryService.evaluateTwinRecovery(
                    twin.id,
                    anomaly,
                    impactAssessment,
                    relevantAttackActive,
                );

                if (transition === RecoveryTransition.VERIFYING) {
                    if (twin.state !== DeviceSecurityState.RECOVERING) {
                        this.transitionState(twin.nodeMac, DeviceSecurityState.RECOVERING);
                    }
                    this.securityEvents.emit({
                        type: SecurityEventType.RECOVERY_STARTED,
                        severity: SecurityEventSeverity.INFO,
                        source: twin.id,
                        description: "Recovery verification started after the attack ended.",
                        metadata: { twinId: twin.id },
                    });
                }

                if (transition === RecoveryTransition.RECOVERED) {
                    if (twin.state === DeviceSecurityState.RECOVERING) {
                        this.transitionState(twin.nodeMac, DeviceSecurityState.RECOVERED);
                    }
                    this.securityEvents.emit({
                        type: SecurityEventType.RECOVERY_COMPLETED,
                        severity: SecurityEventSeverity.INFO,
                        source: twin.id,
                        description: "Recovery completed after five consecutive healthy evaluations.",
                        metadata: { twinId: twin.id },
                    });
                    this.recoveryService.cleanupTwinRecovery(twin.id);
                }
            } else {
                this.recoveryService.cleanupTwinRecovery(twin.id);
            }

            // 10. Recovery Evaluation
            for (const execution of allActiveMitigations) {
                // Do not recover one mitigation while a different attack is still
                // active against the same Digital Twin.
                const relevantAttackActive = activeAttacks.some(a => a.config.targetNodeMac === twin.nodeMac);
                
                const transition = this.recoveryService.evaluateRecovery(execution, anomaly, impactAssessment, relevantAttackActive);
                
                if (transition === RecoveryTransition.VERIFYING) {
                    this.mitigationEngine.transitionStatus(execution.id, MitigationStatus.VERIFYING);
                    if (twin.state === DeviceSecurityState.UNDER_ATTACK || twin.state === DeviceSecurityState.SUSPICIOUS) {
                        this.transitionState(twin.nodeMac, DeviceSecurityState.RECOVERING);
                    }
                    this.securityEvents.emit({
                        type: SecurityEventType.RECOVERY_STARTED,
                        severity: SecurityEventSeverity.INFO,
                        source: twin.id,
                        relatedAttackId: execution.relatedAttackId,
                        description: `Recovery verification started for mitigation ${execution.type}`,
                        metadata: { twinId: twin.id, mitigationId: execution.id, mitigationType: execution.type, relatedAttackId: execution.relatedAttackId ?? "None" }
                    });
                }
                
                if (transition === RecoveryTransition.RECOVERED) {
                    this.mitigationEngine.transitionStatus(execution.id, MitigationStatus.RECOVERED);
                    if (twin.state === DeviceSecurityState.RECOVERING) {
                        this.transitionState(twin.nodeMac, DeviceSecurityState.RECOVERED);
                    }
                    this.securityEvents.emit({
                        type: SecurityEventType.RECOVERY_COMPLETED,
                        severity: SecurityEventSeverity.INFO,
                        source: twin.id,
                        relatedAttackId: execution.relatedAttackId,
                        description: `Recovery completed for mitigation ${execution.type}`,
                        metadata: { twinId: twin.id, mitigationId: execution.id, mitigationType: execution.type, relatedAttackId: execution.relatedAttackId ?? "None" }
                    });
                    
                    // Note: AttackEngine will stop it naturally if we are recovered
                    this.mitigationEngine.stopMitigation(execution.id);
                    this.recoveryService.cleanupForMitigation(execution.id);
                } else if (execution.status === MitigationStatus.STOPPED) {
                    // It was stopped manually or otherwise outside recovery
                    this.securityEvents.emit({
                        type: SecurityEventType.MITIGATION_STOPPED,
                        severity: SecurityEventSeverity.INFO,
                        source: twin.id,
                        description: `Mitigation stopped: ${execution.type}`,
                        metadata: { twinId: twin.id, mitigationId: execution.id, mitigationType: execution.type }
                    });
                    this.recoveryService.cleanupForMitigation(execution.id);
                }
            }
            
            // Clean out stopped/recovered from twin's active list
            twin.setActiveMitigations(twin.activeMitigations.filter(m => m.status === MitigationStatus.APPLIED || m.status === MitigationStatus.VERIFYING));
            
            // 11. Incident Snapshot Sync for UI presentation
            const latestIncident = this.incidentCorrelation.getLatestIncidentForTwin(twin.id);
            if (latestIncident) {
                twin.setLatestIncident(latestIncident.id, latestIncident.status);
            } else {
                twin.setLatestIncident(null, null);
            }
        }

        const now = Date.now();
        for (const [attackId, lifecycle] of this._incidentDemoLifecycles) {
            if (now >= lifecycle.expiresAt) this._incidentDemoLifecycles.delete(attackId);
        }

        this._notifyChange();
    }

    /**
     * Applies bounded operational effects of an active simulated attack to the target
     * Digital Twin. These are simulation-only telemetry effects; no real network
     * controls or external systems are touched.
     */
    private _applyAttackTelemetryEffects(twin: DigitalTwin, attack: AttackExecution, connectionLatency: number): void {
        const intensity = Math.max(1, Math.min(10, Number(attack.config.intensity) || 1));

        // Keep the attack identity on the target Twin before detection so anomaly,
        // risk, and impact events can all carry the same attack correlation ID.
        if (twin.currentAttackId !== attack.id) {
            twin.setCurrentAttack(attack.id);
            if (attack.config.type === AttackType.SENSOR_SPOOF || attack.config.type === AttackType.BRUTE_FORCE || attack.config.type === AttackType.PORT_SCAN) {
                twin.transitionTo(DeviceSecurityState.SUSPICIOUS);
            } else {
                twin.transitionTo(DeviceSecurityState.UNDER_ATTACK);
            }
        }

        const mitigationFactor =
            attack.config.type === AttackType.DOS || attack.config.type === AttackType.MQTT_FLOOD
                ? this.mitigationEngine.getMitigationFactor(attack.id, MitigationType.TRAFFIC_RATE_LIMIT)
                : 1;

        if (attack.config.type === AttackType.DOS || attack.config.type === AttackType.MQTT_FLOOD) {
            const packetRate = (attack.config.type === AttackType.DOS ? intensity * 20 : intensity * 15) * mitigationFactor;
            const bytesPerPacket = attack.config.type === AttackType.MQTT_FLOOD ? 1024 : 96;
            const attackBandwidth = packetRate * bytesPerPacket;

            // Make the simulated operational impact deterministic enough to exercise
            // the Phase 5/6 path at realistic attack intensities.  The impact model
            // still consumes only Digital Twin telemetry; these are bounded,
            // simulation-only telemetry overrides. At intensity 5 before mitigation
            // this produces roughly 700 ms latency and 50% loss, which crosses the
            // MEDIUM performance-impact threshold. A 50% traffic-rate mitigation
            // immediately reduces both values and therefore gives recovery a real
            // measurable effect.
            const attackLatency = Math.min(1200, Math.max(0, connectionLatency) + 100 + intensity * 120 * mitigationFactor);
            const attackPacketLoss = Math.min(50, intensity * 10 * mitigationFactor);

            twin.applyAttackOverrides({
                packetsPerSecond: packetRate,
                bandwidthUsage: attackBandwidth,
                latency: attackLatency,
                packetLoss: attackPacketLoss,
            }, attack.id);
            return;
        }

        if (attack.config.type === AttackType.SENSOR_SPOOF) {
            const params = attack.config.parameters as SensorSpoofParameters;
            if (!this.mitigationEngine.isSensorSpoofSuppressed(attack.id)) {
                twin.applyAttackOverrides({ [params.targetField]: params.spoofValue }, attack.id);
            }
        }

    }

    private _advanceIncidentDemoLifecycle(
        twin: DigitalTwin,
        attacks: readonly AttackExecution[],
        now: number,
    ): void {
        for (const attack of attacks) {
            let lifecycle = this._incidentDemoLifecycles.get(attack.id);
            if (!lifecycle) {
                const incident = this.incidentCorrelation.incidents().find(
                    item => item.attackId === attack.id &&
                        item.status !== IncidentStatus.RECOVERED && item.status !== IncidentStatus.CLOSED,
                );
                if (!incident) continue;
                lifecycle = {
                    twinId: twin.id,
                    mitigationDueAt: attack.createdAt.getTime() + randomInt(
                        INCIDENT_MITIGATION_DELAY_MIN_MS,
                        INCIDENT_MITIGATION_DELAY_MAX_MS,
                    ),
                    expiresAt: attack.createdAt.getTime() + 20_000,
                    mitigationApplied: false,
                    recoveryStarted: false,
                };
                this._incidentDemoLifecycles.set(attack.id, lifecycle);
            }

            const mitigationType = this._mitigationForAttack(attack.config.type);
            let mitigation: MitigationExecution | null | undefined = this.mitigationEngine.mitigations.find(
                item => item.relatedAttackId === attack.id &&
                    item.twinId === twin.id &&
                    [MitigationStatus.APPLIED, MitigationStatus.VERIFYING, MitigationStatus.RECOVERED].includes(item.status),
            );

            if (!lifecycle.mitigationApplied && !mitigation && now >= lifecycle.mitigationDueAt) {
                const recommendation = {
                    mitigationType,
                    twinId: twin.id,
                    relatedAttackId: attack.id,
                    relatedAttackType: attack.config.type,
                    reason: "Timed simulated incident response for project demonstration",
                };
                this.securityEvents.emit({
                    type: SecurityEventType.MITIGATION_RECOMMENDED,
                    severity: SecurityEventSeverity.INFO,
                    source: twin.id,
                    relatedAttackId: attack.id,
                    description: `Mitigation recommended: ${mitigationType}`,
                    metadata: { twinId: twin.id, mitigationType, relatedAttackId: attack.id, reason: recommendation.reason },
                });
                mitigation = this.mitigationEngine.applyMitigation(recommendation);
                if (mitigation) {
                    this.securityEvents.emit({
                        type: SecurityEventType.MITIGATION_APPLIED,
                        severity: SecurityEventSeverity.MEDIUM,
                        source: twin.id,
                        relatedAttackId: attack.id,
                        description: `Mitigation applied: ${mitigationType}`,
                        metadata: { twinId: twin.id, mitigationId: mitigation.id, mitigationType, relatedAttackId: attack.id },
                    });
                }
            }

            if (mitigation && !lifecycle.mitigationApplied) {
                lifecycle.mitigationApplied = true;
            }
            if (!lifecycle.mitigationApplied || !mitigation) continue;

            if (!lifecycle.recoveryStarted) {
                lifecycle.recoveryStarted = true;
                lifecycle.recoveryDueAt = now + randomInt(
                    INCIDENT_RECOVERY_DELAY_MIN_MS,
                    INCIDENT_RECOVERY_DELAY_MAX_MS,
                );
                this.securityEvents.emit({
                    type: SecurityEventType.RECOVERY_STARTED,
                    severity: SecurityEventSeverity.INFO,
                    source: twin.id,
                    relatedAttackId: attack.id,
                    description: "Incident recovery workflow started after simulated mitigation.",
                    metadata: { twinId: twin.id, mitigationId: mitigation.id, mitigationType, relatedAttackId: attack.id },
                });
                continue;
            }

            if (lifecycle.recoveryDueAt !== undefined && now >= lifecycle.recoveryDueAt) {
                this.securityEvents.emit({
                    type: SecurityEventType.RECOVERY_COMPLETED,
                    severity: SecurityEventSeverity.INFO,
                    source: twin.id,
                    relatedAttackId: attack.id,
                    description: "Simulated incident recovery completed.",
                    metadata: { twinId: twin.id, mitigationId: mitigation.id, mitigationType, relatedAttackId: attack.id },
                });
                this._incidentDemoLifecycles.delete(attack.id);
            }
        }
    }

    private _mitigationForAttack(attackType: AttackType): MitigationType {
        switch (attackType) {
            case AttackType.DOS:
            case AttackType.MQTT_FLOOD:
                return MitigationType.TRAFFIC_RATE_LIMIT;
            case AttackType.SENSOR_SPOOF:
                return MitigationType.SENSOR_VALIDATION;
            case AttackType.BRUTE_FORCE:
                return MitigationType.AUTH_RATE_LIMIT;
            case AttackType.PORT_SCAN:
                return MitigationType.SCAN_RATE_LIMIT;
        }
    }

    /**
     * Handles the outcome of the anomaly detector, dispatching debounced security events
     * and performing valid DeviceSecurityState transitions.
     */
    private _handleAnomalyResult(twin: DigitalTwin, anomaly: AnomalyResult): void {
        if (!anomaly.isArmed) return;

        let state = this._anomalyStates.get(twin.id);
        if (!state) {
            state = { severity: AnomalySeverity.NORMAL, clearStreak: 0 };
            this._anomalyStates.set(twin.id, state);
        }

        const isCurrentlyAnomalous = anomaly.severity !== AnomalySeverity.NORMAL;
        
        // Handle Clear Logic (Hysteresis)
        if (!isCurrentlyAnomalous && state.severity !== AnomalySeverity.NORMAL) {
            // Anomaly dropped below threshold, check if it clears cleanly (score < 2.0 for 5 ticks)
            if (anomaly.score < 2.0) {
                state.clearStreak++;
                if (state.clearStreak >= 5) {
                    state.severity = AnomalySeverity.NORMAL;
                    state.clearStreak = 0;
                    
                    this.securityEvents.emit({
                        type: SecurityEventType.ANOMALY_CLEARED,
                        severity: SecurityEventSeverity.INFO,
                        source: twin.id,
                        description: `Anomaly behavior cleared for device ${twin.id}. Telemetry has normalized.`,
                        metadata: { twinId: twin.id, score: anomaly.score }
                    });

                    // RecoveryService owns the state demotion so ONLINE/RECOVERED
                    // cannot be reached until attack, anomaly, impact, and healthy
                    // streak conditions have all been satisfied.
                }
            } else {
                // Fluctuating slightly above 2.0, break clear streak
                state.clearStreak = 0;
            }
            return;
        }

        // Reset clear streak if anomaly returns
        if (isCurrentlyAnomalous) {
            state.clearStreak = 0;
        }

        // Handle Escalation / Debouncing
        const severityValues = {
            [AnomalySeverity.NORMAL]: 0,
            [AnomalySeverity.LOW]: 1,
            [AnomalySeverity.MEDIUM]: 2,
            [AnomalySeverity.HIGH]: 3,
            [AnomalySeverity.CRITICAL]: 4
        };

        const prevLevel = severityValues[state.severity];
        const newLevel = severityValues[anomaly.severity];

        if (newLevel > prevLevel) {
            // Escalation detected!
            state.severity = anomaly.severity;
            
            this.securityEvents.emit({
                type: SecurityEventType.ANOMALY_DETECTED,
                severity: this._mapAnomalySeverityToEventSeverity(anomaly.severity),
                source: twin.id,
                description: `Anomaly detected: ${anomaly.severity} severity on ${anomaly.maxFeature}`,
                metadata: {
                    twinId: twin.id,
                    anomalyScore: anomaly.score,
                    dominantFeature: anomaly.maxFeature ?? "None",
                    featureDetails: JSON.stringify(anomaly.featureDetails),
                    ...(anomaly.relatedAttackId ? { relatedAttackId: anomaly.relatedAttackId } : {})
                }
            });

            // Transition Device Security State according to mapped matrix
            if (anomaly.severity === AnomalySeverity.LOW || anomaly.severity === AnomalySeverity.MEDIUM) {
                if (twin.state === DeviceSecurityState.ONLINE) {
                    this.transitionState(twin.nodeMac, DeviceSecurityState.SUSPICIOUS);
                }
            } else if (anomaly.severity === AnomalySeverity.HIGH || anomaly.severity === AnomalySeverity.CRITICAL) {
                if (twin.state === DeviceSecurityState.SUSPICIOUS || twin.state === DeviceSecurityState.ONLINE) {
                    this.transitionState(twin.nodeMac, DeviceSecurityState.UNDER_ATTACK);
                }
            }
        }
    }

    private _mapAnomalySeverityToEventSeverity(severity: AnomalySeverity): SecurityEventSeverity {
        switch (severity) {
            case AnomalySeverity.LOW: return SecurityEventSeverity.LOW;
            case AnomalySeverity.MEDIUM: return SecurityEventSeverity.MEDIUM;
            case AnomalySeverity.HIGH: return SecurityEventSeverity.HIGH;
            case AnomalySeverity.CRITICAL: return SecurityEventSeverity.CRITICAL;
            default: return SecurityEventSeverity.INFO;
        }
    }

    /**
     * Increments the revision counter to trigger signal updates.
     */
    private _notifyChange(): void {
        this._revision.update(r => r + 1);
    }

    /**
     * Maps a security state to an event severity level.
     */
    private _severityForStateChange(state: DeviceSecurityState): SecurityEventSeverity {
        switch (state) {
            case DeviceSecurityState.ONLINE:
            case DeviceSecurityState.RECOVERED:
                return SecurityEventSeverity.INFO;
            case DeviceSecurityState.OFFLINE:
            case DeviceSecurityState.DEGRADED:
                return SecurityEventSeverity.LOW;
            case DeviceSecurityState.SUSPICIOUS:
            case DeviceSecurityState.RECOVERING:
                return SecurityEventSeverity.MEDIUM;
            case DeviceSecurityState.UNDER_ATTACK:
                return SecurityEventSeverity.HIGH;
            case DeviceSecurityState.COMPROMISED:
                return SecurityEventSeverity.CRITICAL;
        }
    }

    /**
     * Handles hysteresis and debouncing for Phase 4 RiskLevel transitions.
     * Escalate immediately, de-escalate only after 3 consecutive ticks.
     */
    private _handleRiskAssessment(twin: DigitalTwin, risk: RiskAssessment): void {
        let debounce = this._riskDebounceStates.get(twin.id);
        if (!debounce) {
            debounce = { lastEmittedLevel: null, candidateLevel: null, consecutiveTicks: 0 };
            this._riskDebounceStates.set(twin.id, debounce);
        }

        // Initialize state without spamming an event for baseline assessment
        if (debounce.lastEmittedLevel === null) {
            debounce.lastEmittedLevel = risk.level;
            return;
        }

        // If level hasn't changed, reset candidacy tracking and do nothing
        if (risk.level === debounce.lastEmittedLevel) {
            debounce.candidateLevel = null;
            debounce.consecutiveTicks = 0;
            return;
        }

        const levelValues: Record<RiskLevel, number> = {
            [RiskLevel.LOW]: 1,
            [RiskLevel.MEDIUM]: 2,
            [RiskLevel.HIGH]: 3,
            [RiskLevel.CRITICAL]: 4
        };

        const oldVal = levelValues[debounce.lastEmittedLevel];
        const newVal = levelValues[risk.level];

        if (newVal > oldVal) {
            // Escalation: emit immediately
            this._emitRiskChanged(twin, debounce.lastEmittedLevel, risk);
            debounce.lastEmittedLevel = risk.level;
            debounce.candidateLevel = null;
            debounce.consecutiveTicks = 0;
        } else {
            // De-escalation: requires 3 consecutive ticks
            if (debounce.candidateLevel === risk.level) {
                debounce.consecutiveTicks++;
                if (debounce.consecutiveTicks >= 3) {
                    this._emitRiskChanged(twin, debounce.lastEmittedLevel, risk);
                    debounce.lastEmittedLevel = risk.level;
                    debounce.candidateLevel = null;
                    debounce.consecutiveTicks = 0;
                }
            } else {
                debounce.candidateLevel = risk.level;
                debounce.consecutiveTicks = 1;
            }
        }
    }

    private _emitRiskChanged(twin: DigitalTwin, previousLevel: RiskLevel, currentRisk: RiskAssessment): void {
        const metadata: Record<string, string | number | boolean> = {
            twinId: twin.id,
            previousRiskLevel: previousLevel,
            currentRiskLevel: currentRisk.level,
            currentScore: currentRisk.totalScore,
            primaryFactor: currentRisk.primaryFactorName
        };

        const correlatedAttackId = twin.currentAttackId ?? this._recentAttackContexts.get(twin.id)?.execution.id;
        if (correlatedAttackId) {
            metadata['attackId'] = correlatedAttackId;
        }

        this.securityEvents.emit({
            type: SecurityEventType.RISK_CHANGED,
            severity: this._mapRiskLevelToSeverity(currentRisk.level),
            source: twin.id,
            description: `Risk Level transition: ${previousLevel.toUpperCase()} → ${currentRisk.level.toUpperCase()} (${currentRisk.totalScore}/100)`,
            metadata
        });
    }

    private _mapRiskLevelToSeverity(level: RiskLevel): SecurityEventSeverity {
        switch (level) {
            case RiskLevel.LOW: return SecurityEventSeverity.INFO;
            case RiskLevel.MEDIUM: return SecurityEventSeverity.MEDIUM;
            case RiskLevel.HIGH: return SecurityEventSeverity.HIGH;
            case RiskLevel.CRITICAL: return SecurityEventSeverity.CRITICAL;
        }
    }

    /**
     * Handles hysteresis and debouncing for Phase 5 ImpactLevel transitions.
     * Escalate immediately, de-escalate only after 3 consecutive ticks.
     */
    private _handleImpactAssessment(twin: DigitalTwin, impact: ImpactAssessment): void {
        let debounce = this._impactDebounceStates.get(twin.id);
        if (!debounce) {
            debounce = { lastEmittedLevel: null, candidateLevel: null, consecutiveTicks: 0 };
            this._impactDebounceStates.set(twin.id, debounce);
        }

        // Initialize state without spamming an event for baseline assessment
        if (debounce.lastEmittedLevel === null) {
            debounce.lastEmittedLevel = impact.level;
            return;
        }

        // If level hasn't changed, reset candidacy tracking and do nothing
        if (impact.level === debounce.lastEmittedLevel) {
            debounce.candidateLevel = null;
            debounce.consecutiveTicks = 0;
            return;
        }

        const levelValues: Record<ImpactLevel, number> = {
            [ImpactLevel.LOW]: 1,
            [ImpactLevel.MEDIUM]: 2,
            [ImpactLevel.HIGH]: 3,
            [ImpactLevel.CRITICAL]: 4
        };

        const oldVal = levelValues[debounce.lastEmittedLevel];
        const newVal = levelValues[impact.level];

        if (newVal > oldVal) {
            // Escalation: emit immediately
            this._emitImpactChanged(twin, debounce.lastEmittedLevel, impact);
            debounce.lastEmittedLevel = impact.level;
            debounce.candidateLevel = null;
            debounce.consecutiveTicks = 0;
        } else {
            // De-escalation: requires 3 consecutive ticks
            if (debounce.candidateLevel === impact.level) {
                debounce.consecutiveTicks++;
                if (debounce.consecutiveTicks >= 3) {
                    this._emitImpactChanged(twin, debounce.lastEmittedLevel, impact);
                    debounce.lastEmittedLevel = impact.level;
                    debounce.candidateLevel = null;
                    debounce.consecutiveTicks = 0;
                }
            } else {
                debounce.candidateLevel = impact.level;
                debounce.consecutiveTicks = 1;
            }
        }
    }

    private _emitImpactChanged(twin: DigitalTwin, previousLevel: ImpactLevel, currentImpact: ImpactAssessment): void {
        const metadata: Record<string, string | number | boolean> = {
            twinId: twin.id,
            previousImpactLevel: previousLevel,
            currentImpactLevel: currentImpact.level,
            currentScore: currentImpact.overallScore,
            primaryDimension: currentImpact.primaryImpactDimension
        };

        const correlatedAttackId = twin.currentAttackId ?? this._recentAttackContexts.get(twin.id)?.execution.id;
        if (correlatedAttackId) {
            metadata['attackId'] = correlatedAttackId;
        }

        this.securityEvents.emit({
            type: SecurityEventType.IMPACT_CHANGED,
            severity: this._mapImpactLevelToSeverity(currentImpact.level),
            source: twin.id,
            description: `Impact Level transition: ${previousLevel.toUpperCase()} → ${currentImpact.level.toUpperCase()} (${currentImpact.overallScore}/100)`,
            metadata
        });
    }

    private _mapImpactLevelToSeverity(level: ImpactLevel): SecurityEventSeverity {
        switch (level) {
            case ImpactLevel.LOW: return SecurityEventSeverity.INFO;
            case ImpactLevel.MEDIUM: return SecurityEventSeverity.MEDIUM;
            case ImpactLevel.HIGH: return SecurityEventSeverity.HIGH;
            case ImpactLevel.CRITICAL: return SecurityEventSeverity.CRITICAL;
        }
    }

    /**
     * Cleanup on service destruction — stops the telemetry loop.
     */
    public ngOnDestroy(): void {
        this._stopTelemetryLoop();
        this._networkSubs.unsubscribe();
    }
}
