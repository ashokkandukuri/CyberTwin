import { Injectable, signal, computed, Signal, WritableSignal, OnDestroy } from "@angular/core";
import { 
    AttackConfig, 
    AttackType, 
    MAX_ACTIVE_ATTACKS, 
    MAX_ATTACK_DURATION_MS, 
    MIN_ATTACK_DURATION_MS,
    MAX_INTENSITY,
    MIN_INTENSITY,
    DosParameters,
    MqttFloodParameters,
    SensorSpoofParameters,
    BruteForceParameters,
    PortScanParameters,
    ATTACK_TICK_INTERVAL_MS,
    MAX_SIMULATED_EVENTS_PER_ATTACK,
    MAX_MQTT_PAYLOAD_SIZE,
    MAX_PORT_SCAN_RANGE
} from "@models/attack-types";
import { AttackExecution, AttackStatus } from "@models/attack-execution";
import { NetworkService } from "./network.service";
import { SecurityEventService } from "./security-event.service";
import { SecurityEventType, SecurityEventSeverity } from "@models/security-event";
import { NodeType } from "@models/node";
import { Packet } from "@models/packet";
import { DeviceSecurityState } from "@models/device-state";
import { randomInt } from "@utils/random";
import { MitigationEngineService } from "./mitigation-engine.service";
import { MitigationType } from "@models/mitigation";
import { Subscription } from "rxjs";

export interface AttackValidationResult {
    valid: boolean;
    error?: string;
    clampedConfig?: AttackConfig;
}

@Injectable({ providedIn: "root" })
export class AttackEngineService implements OnDestroy {
    private readonly _executions: WritableSignal<AttackExecution[]> = signal([]);
    /** Last Phantom Attacker UI selection per source node, retained while the app session is alive. */
    private readonly _lastAttackSelection = new Map<string, { attackId: string; targetIp?: string }>();
    private readonly _networkResetSubscription: Subscription;

    public readonly activeAttacks: Signal<AttackExecution[]> = computed(() => 
        this._executions().filter(e => e.status === AttackStatus.RUNNING)
    );

    public readonly attackHistory: Signal<AttackExecution[]> = computed(() => 
        this._executions().filter(e => e.status !== AttackStatus.RUNNING)
    );

    public readonly attackCount: Signal<number> = computed(() => this._executions().length);

    /** Returns the most recently selected attack/target for a Phantom Attacker source. */
    public getLastAttackSelection(sourceNodeMac: string): { attackId: string; targetIp?: string } | undefined {
        const value = this._lastAttackSelection.get(sourceNodeMac);
        return value ? { ...value } : undefined;
    }

    /** Remembers the Phantom Attacker UI selection for the current application session. */
    public rememberAttackSelection(sourceNodeMac: string, attackId: string, targetIp?: string): void {
        if (!sourceNodeMac || !attackId) return;
        this._lastAttackSelection.set(sourceNodeMac, { attackId, targetIp });
    }

    /** Finds a recently completed/stopped attack for delayed telemetry correlation. */
    public getRecentAttackForTarget(targetNodeMac: string, maxAgeMs: number): AttackExecution | undefined {
        const cutoff = Date.now() - Math.max(0, maxAgeMs);
        return this._executions()
            .filter(execution =>
                execution.config.targetNodeMac === targetNodeMac &&
                execution.status === AttackStatus.COMPLETED &&
                execution.lastUpdate.getTime() >= cutoff
            )
            .sort((a, b) => b.lastUpdate.getTime() - a.lastUpdate.getTime())[0];
    }

    constructor(
        private readonly networkService: NetworkService,
        private readonly securityEventService: SecurityEventService,
        private readonly mitigationEngine: MitigationEngineService
    ) {
        this._networkResetSubscription = this.networkService.onNetworkReset.subscribe(() => this.reset());
    }

    public ngOnDestroy(): void {
        this._networkResetSubscription.unsubscribe();
        this.reset();
    }

    public validateConfig(config: AttackConfig): AttackValidationResult {
        if (!Object.values(AttackType).includes(config.type)) {
            return { valid: false, error: "Invalid attack type." };
        }

        const sourceNode = this.networkService.getNode(config.sourceNodeMac);
        if (!sourceNode) {
            return { valid: false, error: "Source node not found." };
        }
        if (!NodeType.AttackerTypes.includes(sourceNode.type)) {
            return { valid: false, error: "Source node is not allowed to attack." };
        }

        const targetNode = this.networkService.getNode(config.targetNodeMac);
        if (!targetNode) {
            return { valid: false, error: "Target node not found." };
        }
        
        if (config.sourceNodeMac === config.targetNodeMac) {
            return { valid: false, error: "Source and target cannot be the same node." };
        }

        // Network connection requirements:
        // DOS, MQTT_FLOOD, PORT_SCAN -> network connection REQUIRED
        // SENSOR_SPOOF, BRUTE_FORCE -> network connection NOT required
        const requiresNetwork = [
            AttackType.DOS,
            AttackType.MQTT_FLOOD,
            AttackType.PORT_SCAN
        ].includes(config.type);

        if (requiresNetwork && !targetNode.connected) {
            return { valid: false, error: "Target node must be connected to the network for this attack type." };
        }

        if (!this.networkService.getNode(config.targetNodeMac)) {
            return { valid: false, error: "Target node does not exist in the network." };
        }

        if (this.activeAttacks().length >= MAX_ACTIVE_ATTACKS) {
            return { valid: false, error: `Maximum of ${MAX_ACTIVE_ATTACKS} active attacks reached.` };
        }

        const isDuplicate = this.activeAttacks().some(e => 
            e.config.type === config.type && e.config.targetNodeMac === config.targetNodeMac
        );
        if (isDuplicate) {
            return { valid: false, error: "An identical attack on this target is already running." };
        }

        let durationMs = config.durationMs;
        if (typeof durationMs !== "number" || isNaN(durationMs) || !isFinite(durationMs)) {
            return { valid: false, error: "Invalid duration." };
        }
        durationMs = Math.max(MIN_ATTACK_DURATION_MS, Math.min(MAX_ATTACK_DURATION_MS, durationMs));

        let intensity = config.intensity;
        if (typeof intensity !== "number" || isNaN(intensity) || !isFinite(intensity) || intensity <= 0) {
            return { valid: false, error: "Invalid intensity." };
        }
        intensity = Math.max(MIN_INTENSITY, Math.min(MAX_INTENSITY, intensity));

        // Type-specific validation
        if (config.type === AttackType.DOS) {
            const params = config.parameters as DosParameters;
            if (!params || typeof params.dstPort !== "number" || !Array.isArray(params.ttlRange) || params.ttlRange.length !== 2) {
                return { valid: false, error: "Invalid parameters for DOS attack." };
            }
        } else if (config.type === AttackType.MQTT_FLOOD) {
            const params = config.parameters as MqttFloodParameters;
            if (!params || typeof params.topic !== "string" || typeof params.payloadSizeBytes !== "number") {
                return { valid: false, error: "Invalid parameters for MQTT Flood attack." };
            }
            if (params.payloadSizeBytes <= 0 || params.payloadSizeBytes > MAX_MQTT_PAYLOAD_SIZE) {
                return { valid: false, error: `Payload size must be between 1 and ${MAX_MQTT_PAYLOAD_SIZE} bytes.` };
            }
        } else if (config.type === AttackType.SENSOR_SPOOF) {
            const params = config.parameters as SensorSpoofParameters;
            if (!params || typeof params.targetField !== "string" || typeof params.spoofValue !== "number") {
                return { valid: false, error: "Invalid parameters for Sensor Spoof attack." };
            }
            const allowedFields = [
                "cpuUtilization", "memoryUtilization", "packetsPerSecond", 
                "bandwidthUsage", "latency", "packetLoss", "connectionCount", 
                "temperature", "batteryLevel", "authFailures", "sensorReading"
            ];
            if (!allowedFields.includes(params.targetField)) {
                return { valid: false, error: `Field '${params.targetField}' is not a valid spoofable telemetry field.` };
            }
            if (!Number.isFinite(params.spoofValue)) {
                return { valid: false, error: "Spoof value must be a finite number." };
            }
        } else if (config.type === AttackType.BRUTE_FORCE) {
            const params = config.parameters as BruteForceParameters;
            if (!params || typeof params.targetService !== "string") {
                return { valid: false, error: "Invalid parameters for Brute Force attack." };
            }
            const allowedServices = ["SSH", "HTTP", "MQTT", "TELNET"];
            if (!allowedServices.includes(params.targetService.toUpperCase())) {
                return { valid: false, error: `Target service '${params.targetService}' is not supported.` };
            }
        } else if (config.type === AttackType.PORT_SCAN) {
            const params = config.parameters as PortScanParameters;
            if (!params || !Array.isArray(params.portRange) || params.portRange.length !== 2) {
                return { valid: false, error: "Invalid parameters for Port Scan attack." };
            }
            const [startPort, endPort] = params.portRange;
            if (!Number.isInteger(startPort) || !Number.isInteger(endPort)) {
                return { valid: false, error: "Port bounds must be finite integers." };
            }
            if (startPort < 1 || startPort > 65535 || endPort < 1 || endPort > 65535) {
                return { valid: false, error: "Port bounds must be between 1 and 65535." };
            }
            if (startPort > endPort) {
                return { valid: false, error: "startPort must be less than or equal to endPort." };
            }
            if ((endPort - startPort + 1) > MAX_PORT_SCAN_RANGE) {
                return { valid: false, error: `Requested scan range exceeds MAX_PORT_SCAN_RANGE (${MAX_PORT_SCAN_RANGE}).` };
            }
        }

        const clampedConfig: AttackConfig = {
            ...config,
            durationMs,
            intensity
        };

        return { valid: true, clampedConfig };
    }

    public launchAttack(config: AttackConfig): AttackValidationResult {
        const validation = this.validateConfig(config);
        if (!validation.valid || !validation.clampedConfig) {
            return validation;
        }

        const execution = new AttackExecution(validation.clampedConfig);
        
        this._executions.update(executions => [...executions, execution]);
        
        execution.transitionTo(AttackStatus.CONFIGURED);

        // Start execution
        execution.transitionTo(AttackStatus.RUNNING);

        this.securityEventService.emit({
            type: SecurityEventType.ATTACK_STARTED,
            severity: SecurityEventSeverity.HIGH,
            source: config.sourceNodeMac,
            target: config.targetNodeMac,
            description: `Attack ${config.type} started from ${config.sourceNodeMac} to ${config.targetNodeMac}`,
            relatedAttackId: execution.id,
            metadata: {
                attackType: config.type,
                durationMs: validation.clampedConfig.durationMs,
                intensity: validation.clampedConfig.intensity
            }
        });

        // Set up the auto-stop timeout
        execution.timeoutHandle = setTimeout(() => {
            this._completeAttack(execution.id);
        }, validation.clampedConfig.durationMs);


        // Start specific strategy
        if (config.type === AttackType.DOS) {
            this._executeDosAttack(execution);
        } else if (config.type === AttackType.MQTT_FLOOD) {
            this._executeMqttFloodAttack(execution);
        } else if (config.type === AttackType.SENSOR_SPOOF) {
            this._executeSensorSpoofAttack(execution);
        } else if (config.type === AttackType.BRUTE_FORCE) {
            this._executeBruteForceAttack(execution);
        } else if (config.type === AttackType.PORT_SCAN) {
            this._executePortScanAttack(execution);
        }

        return validation;
    }

    private _executeDosAttack(execution: AttackExecution): void {
        const config = execution.config;
        const sourceNode = this.networkService.getNode(config.sourceNodeMac);
        const targetNode = this.networkService.getNode(config.targetNodeMac);
        const params = config.parameters as DosParameters;

        if (!sourceNode || !targetNode) {
            this._failAttack(execution.id, "Nodes disappeared before execution.");
            return;
        }

        const packetsPerTick = config.intensity * 5;
        let tickCount = 0;
        const ticksPerProgress = 10;

        execution.intervalHandle = setInterval(() => {
            if (execution.status !== AttackStatus.RUNNING) return;

            if (execution.generatedPacketCount >= MAX_SIMULATED_EVENTS_PER_ATTACK) {
                this._completeAttack(execution.id);
                return;
            }

            const remaining = MAX_SIMULATED_EVENTS_PER_ATTACK - execution.generatedPacketCount;
            let actualPackets = Math.min(packetsPerTick, remaining);
            
            const mitigationFactor = this.mitigationEngine.getMitigationFactor(execution.id, MitigationType.TRAFFIC_RATE_LIMIT);
            actualPackets = Math.ceil(actualPackets * mitigationFactor);
            
            if (actualPackets <= 0) return;

            for (let i = 0; i < actualPackets; i++) {
                const packet = Packet.TCPSYN(
                    sourceNode.ip ?? "",
                    targetNode.ip ?? "",
                    randomInt(1024, 65535),
                    params.dstPort
                );
                packet.ttl = randomInt(params.ttlRange[0], params.ttlRange[1]);
                
                sourceNode.sendPacket(packet);
            }
            
            execution.recordPacketsGenerated(actualPackets);
            tickCount++;

            // Throttle progress events (approx every 10 ticks = 2 seconds)
            if (tickCount % ticksPerProgress === 0) {
                this.securityEventService.emit({
                    type: SecurityEventType.ATTACK_PROGRESS,
                    severity: SecurityEventSeverity.MEDIUM,
                    source: config.sourceNodeMac,
                    target: config.targetNodeMac,
                    description: `Attack ${config.type} progressing. Sent ${execution.generatedPacketCount} packets.`,
                    relatedAttackId: execution.id,
                });
            }
        }, ATTACK_TICK_INTERVAL_MS);
    }

    private _executeMqttFloodAttack(execution: AttackExecution): void {
        const config = execution.config;
        const sourceNode = this.networkService.getNode(config.sourceNodeMac);
        const targetNode = this.networkService.getNode(config.targetNodeMac);
        const params = config.parameters as MqttFloodParameters;

        if (!sourceNode || !targetNode) {
            this._failAttack(execution.id, "Nodes disappeared before execution.");
            return;
        }

        // 3 packets per tick at intensity 1, up to 30 at intensity 10.
        const packetsPerTick = config.intensity * 3;
        const dummyPayload = "X".repeat(params.payloadSizeBytes);
        const mqttMessage = `PUBLISH ${params.topic} ${dummyPayload}`;
        let tickCount = 0;
        const ticksPerProgress = 10;

        execution.intervalHandle = setInterval(() => {
            if (execution.status !== AttackStatus.RUNNING) return;

            if (execution.generatedPacketCount >= MAX_SIMULATED_EVENTS_PER_ATTACK) {
                this._completeAttack(execution.id);
                return;
            }

            const remaining = MAX_SIMULATED_EVENTS_PER_ATTACK - execution.generatedPacketCount;
            let actualPackets = Math.min(packetsPerTick, remaining);
            
            const mitigationFactor = this.mitigationEngine.getMitigationFactor(execution.id, MitigationType.TRAFFIC_RATE_LIMIT);
            actualPackets = Math.ceil(actualPackets * mitigationFactor);
            
            if (actualPackets <= 0) return;

            for (let i = 0; i < actualPackets; i++) {
                const packet = Packet.UDP(
                    sourceNode.ip ?? "",
                    targetNode.ip ?? "",
                    randomInt(1024, 65535),
                    1883,
                    mqttMessage
                );
                
                sourceNode.sendPacket(packet);
            }
            
            execution.recordPacketsGenerated(actualPackets);
            tickCount++;

            // Throttle progress events (approx every 10 ticks = 2 seconds)
            if (tickCount % ticksPerProgress === 0) {
                this.securityEventService.emit({
                    type: SecurityEventType.ATTACK_PROGRESS,
                    severity: SecurityEventSeverity.MEDIUM,
                    source: config.sourceNodeMac,
                    target: config.targetNodeMac,
                    description: `Attack ${config.type} progressing. Sent ${execution.generatedPacketCount} packets.`,
                    relatedAttackId: execution.id,
                });
            }
        }, ATTACK_TICK_INTERVAL_MS);
    }

    private _executeSensorSpoofAttack(execution: AttackExecution): void {
        const config = execution.config;
        const params = config.parameters as SensorSpoofParameters;



        let tickCount = 0;
        const ticksPerProgress = 10; // Approx 2 seconds if interval is 200ms, but we'll use 500ms

        execution.intervalHandle = setInterval(() => {
            if (execution.status !== AttackStatus.RUNNING) return;
            

            
            tickCount++;
            
            // Throttled progress events
            if (tickCount % ticksPerProgress === 0) {
                this.securityEventService.emit({
                    type: SecurityEventType.ATTACK_PROGRESS,
                    severity: SecurityEventSeverity.MEDIUM,
                    source: config.sourceNodeMac,
                    target: config.targetNodeMac,
                    description: `Attack ${config.type} progressing. Spoofing ${params.targetField} = ${params.spoofValue}.`,
                    relatedAttackId: execution.id,
                });
            }
        }, 500); // 500ms for sensor spoof
    }

    private _executeBruteForceAttack(execution: AttackExecution): void {
        const config = execution.config;
        const params = config.parameters as BruteForceParameters;

        // 2 attempts per tick at intensity 1, up to 20 at intensity 10.
        const attemptsPerTick = config.intensity * 2;
        const tickInterval = 300; // 300ms for brute force
        let tickCount = 0;
        const ticksPerProgress = 10;

        execution.intervalHandle = setInterval(() => {
            if (execution.status !== AttackStatus.RUNNING) return;

            if (execution.generatedPacketCount >= MAX_SIMULATED_EVENTS_PER_ATTACK) {
                this._completeAttack(execution.id);
                return;
            }

            const remaining = MAX_SIMULATED_EVENTS_PER_ATTACK - execution.generatedPacketCount;
            let actualAttempts = Math.min(attemptsPerTick, remaining);
            
            const mitigationFactor = this.mitigationEngine.getMitigationFactor(execution.id, MitigationType.AUTH_RATE_LIMIT);
            actualAttempts = Math.ceil(actualAttempts * mitigationFactor);
            
            if (actualAttempts <= 0) return;

            for (let i = 0; i < actualAttempts; i++) {
                // Simulated auth failure is tracked via twin telemetry loop
            }
            
            execution.recordPacketsGenerated(actualAttempts);
            tickCount++;

            // Throttle progress events (approx every 10 ticks = 3 seconds)
            if (tickCount % ticksPerProgress === 0) {
                this.securityEventService.emit({
                    type: SecurityEventType.ATTACK_PROGRESS,
                    severity: SecurityEventSeverity.MEDIUM,
                    source: config.sourceNodeMac,
                    target: config.targetNodeMac,
                    description: `Attack ${config.type} progressing against ${params.targetService}. Simulated ${execution.generatedPacketCount} failures.`,
                    relatedAttackId: execution.id,
                });
            }
        }, tickInterval);
    }

    private _executePortScanAttack(execution: AttackExecution): void {
        const config = execution.config;
        const sourceNode = this.networkService.getNode(config.sourceNodeMac);
        const targetNode = this.networkService.getNode(config.targetNodeMac);
        const params = config.parameters as PortScanParameters;

        if (!sourceNode || !targetNode) {
            this._failAttack(execution.id, "Nodes disappeared before execution.");
            return;
        }

        const [startPort, endPort] = params.portRange;
        const totalPorts = endPort - startPort + 1;
        let currentPort = startPort;
        let portsScanned = 0;

        // 2 simulated probes per tick at intensity 1, up to 20 at intensity 10.
        const probesPerTick = config.intensity * 2;
        const tickInterval = 300; // 300ms
        let tickCount = 0;
        const ticksPerProgress = 10;

        execution.intervalHandle = setInterval(() => {
            if (execution.status !== AttackStatus.RUNNING) return;

            if (execution.generatedPacketCount >= MAX_SIMULATED_EVENTS_PER_ATTACK) {
                this._completeAttack(execution.id);
                return;
            }

            const remaining = MAX_SIMULATED_EVENTS_PER_ATTACK - execution.generatedPacketCount;
            let actualProbes = Math.min(probesPerTick, remaining);
            
            const mitigationFactor = this.mitigationEngine.getMitigationFactor(execution.id, MitigationType.SCAN_RATE_LIMIT);
            actualProbes = Math.ceil(actualProbes * mitigationFactor);
            
            if (actualProbes <= 0) return;

            for (let i = 0; i < actualProbes; i++) {
                const packet = Packet.TCPSYN(
                    sourceNode.ip ?? "",
                    targetNode.ip ?? "",
                    randomInt(1024, 65535),
                    currentPort
                );
                
                sourceNode.sendPacket(packet);
                portsScanned++;

                currentPort++;
                if (currentPort > endPort) {
                    currentPort = startPort;
                }
            }
            
            execution.recordPacketsGenerated(actualProbes);
            tickCount++;

            // Throttle progress events (approx every 10 ticks = 3 seconds)
            if (tickCount % ticksPerProgress === 0) {
                this.securityEventService.emit({
                    type: SecurityEventType.ATTACK_PROGRESS,
                    severity: SecurityEventSeverity.MEDIUM,
                    source: config.sourceNodeMac,
                    target: config.targetNodeMac,
                    description: `Attack ${config.type} progressing. Scanned ${portsScanned} ports (out of ${totalPorts} range).`,
                    relatedAttackId: execution.id,
                    metadata: {
                        portsScannedSoFar: portsScanned,
                        totalRequestedRange: totalPorts,
                        intensity: config.intensity
                    }
                });
            }
        }, tickInterval);
    }

    public stopAttack(executionId: string): void {
        const execution = this._executions().find(e => e.id === executionId);
        if (!execution || execution.status !== AttackStatus.RUNNING) {
            return;
        }

        this._cleanupExecutionTimers(execution);
        execution.transitionTo(AttackStatus.STOPPED);



        this.securityEventService.emit({
            type: SecurityEventType.ATTACK_STOPPED,
            severity: SecurityEventSeverity.MEDIUM,
            source: execution.config.sourceNodeMac,
            target: execution.config.targetNodeMac,
            description: `Attack ${execution.config.type} manually stopped.`,
            relatedAttackId: execution.id,
        });
        
        this._triggerUpdates();
    }

    private _completeAttack(executionId: string): void {
        const execution = this._executions().find(e => e.id === executionId);
        if (!execution || execution.status !== AttackStatus.RUNNING) {
            return;
        }

        this._cleanupExecutionTimers(execution);
        execution.transitionTo(AttackStatus.COMPLETED);



        this.securityEventService.emit({
            type: SecurityEventType.ATTACK_COMPLETED,
            severity: SecurityEventSeverity.HIGH,
            source: execution.config.sourceNodeMac,
            target: execution.config.targetNodeMac,
            description: `Attack ${execution.config.type} completed.`,
            relatedAttackId: execution.id,
        });

        this._triggerUpdates();
    }

    private _failAttack(executionId: string, reason: string): void {
        const execution = this._executions().find(e => e.id === executionId);
        if (!execution || execution.status !== AttackStatus.RUNNING) {
            return;
        }

        this._cleanupExecutionTimers(execution);
        execution.transitionTo(AttackStatus.FAILED);



        this.securityEventService.emit({
            type: SecurityEventType.ATTACK_FAILED,
            severity: SecurityEventSeverity.HIGH,
            source: execution.config.sourceNodeMac,
            target: execution.config.targetNodeMac,
            description: `Attack ${execution.config.type} failed: ${reason}`,
            relatedAttackId: execution.id,
        });

        this._triggerUpdates();
    }

    public stopAllAttacks(): void {
        const running = this.activeAttacks();
        for (const execution of running) {
            this.stopAttack(execution.id);
        }
    }

    /** Clears attack executions and their timers when the network is replaced. */
    public reset(): void {
        this.stopAllAttacks();
        this._executions.set([]);
        this._lastAttackSelection.clear();
    }

    private _cleanupExecutionTimers(execution: AttackExecution): void {
        if (execution.intervalHandle) {
            clearInterval(execution.intervalHandle);
            execution.intervalHandle = undefined;
        }
        if (execution.timeoutHandle) {
            clearTimeout(execution.timeoutHandle);
            execution.timeoutHandle = undefined;
        }

    }

    private _triggerUpdates(): void {
        // Triggering signal update explicitly if needed
        this._executions.update(execs => [...execs]);
    }
}
