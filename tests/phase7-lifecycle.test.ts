import "@angular/compiler";
import { AnomalyResult, AnomalySeverity } from "@models/anomaly";
import { AttackExecution, AttackStatus } from "@models/attack-execution";
import { AttackConfig, AttackType } from "@models/attack-types";
import { Connection } from "@models/connection";
import { DeviceSecurityState, isValidTransition } from "@models/device-state";
import { ImpactAssessment, ImpactLevel } from "@models/impact";
import { IncidentStatus } from "@models/incident";
import { EvidenceCategory } from "@models/incident-evidence";
import {
    getIncidentLifecycleProgress,
    INCIDENT_LIFECYCLE_ORDER,
} from "@routes/incidents/incident-lifecycle";
import { MitigationStatus, MitigationType } from "@models/mitigation";
import { NodeType } from "@models/node";
import { RiskLevel } from "@models/risk";
import {
    SecurityEvent,
    SecurityEventSeverity,
    SecurityEventType,
} from "@models/security-event";
import { AnomalyDetectionService } from "@services/anomaly-detection.service";
import { AttackEngineService } from "@services/attack-engine.service";
import { DigitalTwinService } from "@services/digital-twin.service";
import { ImpactAnalysisService } from "@services/impact-analysis.service";
import { IncidentCorrelationService } from "@services/incident-correlation.service";
import { IncidentExplanationService } from "@services/incident-explanation.service";
import { MitigationEngineService } from "@services/mitigation-engine.service";
import { MitigationPolicyService } from "@services/mitigation-policy.service";
import {
    RecoveryService,
    RecoveryTransition,
} from "@services/recovery.service";
import { RiskScoringService } from "@services/risk-scoring.service";
import { SecurityEventService } from "@services/security-event.service";
import { isConnectionUnderActiveAttack } from "@utils/topology-attack-visual";
import assert from "node:assert/strict";
import test from "node:test";
import { Subject } from "rxjs";

const healthyAnomaly: AnomalyResult = {
    twinId: "twin-1",
    timestamp: new Date(),
    isArmed: true,
    score: 0,
    severity: AnomalySeverity.NORMAL,
    featureDetails: [],
};

const lowImpact: ImpactAssessment = {
    twinId: "twin-1",
    timestamp: Date.now(),
    overallScore: 0,
    level: ImpactLevel.LOW,
    performanceImpact: 0,
    integrityImpact: 0,
    authenticationImpact: 0,
    securityImpact: 0,
    potentialBlastRadius: 0,
    primaryImpactDimension: "None",
};

const impactByAttack: ImpactAssessment = {
    ...lowImpact,
    overallScore: 60,
    level: ImpactLevel.HIGH,
    performanceImpact: 30,
    integrityImpact: 30,
    authenticationImpact: 30,
    securityImpact: 30,
    primaryImpactDimension: "Performance",
};

function config(type: AttackType, durationMs = 30_000): AttackConfig {
    const parameters: AttackConfig["parameters"] = {
        [AttackType.DOS]: { dstPort: 53, ttlRange: [32, 128] },
        [AttackType.MQTT_FLOOD]: { topic: "iot/test", payloadSizeBytes: 128 },
        [AttackType.SENSOR_SPOOF]: {
            targetField: "temperature",
            spoofValue: 99,
        },
        [AttackType.BRUTE_FORCE]: { targetService: "SSH" },
        [AttackType.PORT_SCAN]: { portRange: [1, 16] },
    }[type] as AttackConfig["parameters"];
    return {
        type,
        sourceNodeMac: "00:00:00:00:00:01",
        targetNodeMac: "00:00:00:00:00:02",
        durationMs,
        intensity: 5,
        parameters,
    };
}

function runningAttack(type: AttackType): AttackExecution {
    const execution = new AttackExecution(config(type));
    execution.transitionTo(AttackStatus.CONFIGURED);
    execution.transitionTo(AttackStatus.RUNNING);
    return execution;
}

test("incident lifecycle UI keeps the three stages in order", () => {
    assert.deepEqual(INCIDENT_LIFECYCLE_ORDER, [
        "investigating",
        "mitigated",
        "recovered",
    ]);
});

test("incident lifecycle UI marks investigation active and later stages pending", () => {
    const expected = {
        investigating: "active",
        mitigated: "pending",
        recovered: "pending",
    };
    assert.deepEqual(
        getIncidentLifecycleProgress(IncidentStatus.OPEN),
        expected,
    );
    assert.deepEqual(
        getIncidentLifecycleProgress(IncidentStatus.INVESTIGATING),
        expected,
    );
});

test("incident lifecycle UI marks investigation complete and mitigation active", () => {
    assert.deepEqual(
        getIncidentLifecycleProgress(IncidentStatus.MITIGATED),
        {
            investigating: "completed",
            mitigated: "active",
            recovered: "pending",
        },
    );
});

test("incident lifecycle UI shows all stages completed after recovery", () => {
    assert.deepEqual(
        getIncidentLifecycleProgress(IncidentStatus.RECOVERED),
        {
            investigating: "completed",
            mitigated: "completed",
            recovered: "completed",
        },
    );
});

test("topology attack line follows active state for all five attacks and clears on mitigation or stop", () => {
    const connection = {
        node1: { mac: "00:00:00:00:00:03" },
        node2: { mac: "00:00:00:00:00:02" },
    } as Connection;

    for (const type of Object.values(AttackType)) {
        const execution = runningAttack(type);
        assert.equal(
            isConnectionUnderActiveAttack(connection, [execution], []),
            true,
            `${type} marks the target connection as active`,
        );

        const mitigationEvent = {
            type: SecurityEventType.MITIGATION_APPLIED,
            relatedAttackId: execution.id,
            metadata: {},
        } as SecurityEvent;
        assert.equal(
            isConnectionUnderActiveAttack(connection, [execution], [mitigationEvent]),
            false,
            `${type} returns to solid as soon as mitigation is applied`,
        );

        const recoveryEvent = {
            type: SecurityEventType.RECOVERY_COMPLETED,
            relatedAttackId: execution.id,
            metadata: {},
        } as SecurityEvent;
        assert.equal(
            isConnectionUnderActiveAttack(connection, [execution], [recoveryEvent]),
            false,
            `${type} returns to solid when its recovery completes`,
        );

        execution.transitionTo(AttackStatus.DETECTED);
        execution.transitionTo(AttackStatus.MITIGATED);
        execution.transitionTo(AttackStatus.RECOVERED);
        assert.equal(
            isConnectionUnderActiveAttack(connection, [execution], []),
            false,
            `${type} remains solid after recovery`,
        );
    }

    const stoppedAttack = runningAttack(AttackType.PORT_SCAN);
    stoppedAttack.transitionTo(AttackStatus.STOPPED);
    assert.equal(
        isConnectionUnderActiveAttack(connection, [stoppedAttack], []),
        false,
        "manually stopped attacks restore the solid line",
    );
});

test("topology ignores recovered history but preserves a separate active execution", () => {
    const connection = {
        node1: { mac: "00:00:00:00:00:03" },
        node2: { mac: "00:00:00:00:00:02" },
    } as Connection;
    const recoveredExecution = runningAttack(AttackType.MQTT_FLOOD);
    const recoveredHistoryEvent = {
        type: SecurityEventType.RECOVERY_COMPLETED,
        relatedAttackId: recoveredExecution.id,
        metadata: {},
    } as SecurityEvent;

    assert.equal(
        isConnectionUnderActiveAttack(connection, [recoveredExecution], [recoveredHistoryEvent]),
        false,
        "a historical recovery event ends its associated line indicator",
    );

    const newExecution = runningAttack(AttackType.PORT_SCAN);
    assert.equal(
        isConnectionUnderActiveAttack(connection, [recoveredExecution, newExecution], [recoveredHistoryEvent]),
        true,
        "a separate active execution still marks the affected line",
    );
    const unrelatedConnection = {
        node1: { mac: "00:00:00:00:00:04" },
        node2: { mac: "00:00:00:00:00:05" },
    } as Connection;
    assert.equal(
        isConnectionUnderActiveAttack(unrelatedConnection, [newExecution], []),
        false,
        "a separate connection remains solid when it has no active target",
    );

    const newMitigationEvent = {
        type: SecurityEventType.MITIGATION_APPLIED,
        relatedAttackId: newExecution.id,
        metadata: {},
    } as SecurityEvent;
    assert.equal(
        isConnectionUnderActiveAttack(
            connection,
            [recoveredExecution, newExecution],
            [recoveredHistoryEvent, newMitigationEvent],
        ),
        false,
        "the line becomes solid when every affected execution is terminal",
    );

    assert.equal(
        isConnectionUnderActiveAttack(connection, [], []),
        false,
        "reset state with no executions restores all lines",
    );
});

function createLifecycleHarness(
    targetCount = 1,
    useRealPipeline = false,
    targetType: NodeType = NodeType.IOT,
) {
    const reset$ = new Subject<void>();
    const added$ = new Subject<never>();
    const removed$ = new Subject<string>();
    const source = {
        mac: "00:00:00:00:00:01",
        type: NodeType.COMPUTER,
        ip: "192.168.0.2",
        connected: true,
        traffic: [] as unknown[],
        sendPacket(_packet?: unknown) {},
    };
    const targets = Array.from({ length: targetCount }, (_, index) => ({
        mac: `00:00:00:00:00:0${index + 2}`,
        type: targetType,
        ip: `192.168.0.${index + 3}`,
        connected: true,
        traffic: [] as unknown[],
    }));
    source.sendPacket = (packet?: unknown) => {
        targets[0]?.traffic.push(packet);
    };
    const nodes = [source, ...targets];
    const network = {
        onNetworkReset: reset$,
        onNodeAdded: added$,
        onNodeRemoved: removed$,
        nodes,
        router: undefined,
        getNode: (mac: string) => nodes.find((node) => node.mac === mac),
    };
    const correlation = new IncidentCorrelationService();
    const events = new SecurityEventService(correlation);
    const mitigations = new MitigationEngineService();
    const attacks = new AttackEngineService(
        network as never,
        events,
        mitigations,
    );
    const anomaly = useRealPipeline
        ? new AnomalyDetectionService()
        : ({
              processTelemetry: (twin: {
                  id: string;
                  currentAttackId: string | null;
              }) => ({
                  ...healthyAnomaly,
                  twinId: twin.id,
                  relatedAttackId: twin.currentAttackId ?? undefined,
              }),
              cleanupTwin() {},
          } as unknown as AnomalyDetectionService);
    const digitalTwinService = new DigitalTwinService(
        events,
        anomaly,
        new RiskScoringService(),
        attacks,
        new ImpactAnalysisService(network as never),
        useRealPipeline
            ? new MitigationPolicyService()
            : ({ evaluate: () => [] } as unknown as MitigationPolicyService),
        mitigations,
        new RecoveryService(),
        correlation,
        network as never,
    );
    const evaluate = () =>
        (
            digitalTwinService as unknown as {
                _updateAllTelemetry: () => void;
            }
        )._updateAllTelemetry();

    return {
        reset$,
        nodes,
        targets,
        correlation,
        events,
        mitigations,
        attacks,
        digitalTwinService,
        evaluate,
        dispose: () => {
            attacks.ngOnDestroy();
            digitalTwinService.ngOnDestroy();
        },
    };
}

test("all five simulated attack types complete with distinct execution IDs", () => {
    const reset$ = new Subject<void>();
    const source = {
        mac: "00:00:00:00:00:01",
        type: NodeType.COMPUTER,
        ip: "192.168.0.2",
        sendPacket() {},
    };
    const target = {
        mac: "00:00:00:00:00:02",
        type: NodeType.IOT,
        ip: "192.168.0.3",
        connected: true,
    };
    const network = {
        onNetworkReset: reset$,
        getNode: (mac: string) =>
            mac === source.mac
                ? source
                : mac === target.mac
                  ? target
                  : undefined,
    };
    const emitted: unknown[] = [];
    const engine = new AttackEngineService(
        network as never,
        {
            emit: (event: Parameters<SecurityEventService["emit"]>[0]) =>
                emitted.push(event),
        } as never,
        new MitigationEngineService(),
    );

    const ids = new Set<string>();
    for (const type of Object.values(AttackType)) {
        const result = engine.launchAttack(config(type));
        assert.equal(result.valid, true, `${type} should validate and launch`);
        const execution = engine.activeAttacks()[0];
        assert.ok(execution, `${type} should be active`);
        ids.add(execution.id);
        (
            engine as unknown as { _completeAttack: (id: string) => void }
        )._completeAttack(execution.id);
        assert.equal(execution.status, AttackStatus.COMPLETED);
        assert.equal(execution.intervalHandle, undefined);
        assert.equal(execution.timeoutHandle, undefined);
    }
    assert.equal(ids.size, 5);
    assert.equal(emitted.length, 10);
    engine.ngOnDestroy();
});

test("network reset clears active attacks, history, selection, and timers", () => {
    const reset$ = new Subject<void>();
    const source = {
        mac: "00:00:00:00:00:01",
        type: NodeType.COMPUTER,
        ip: "192.168.0.2",
        sendPacket() {},
    };
    const target = {
        mac: "00:00:00:00:00:02",
        type: NodeType.IOT,
        ip: "192.168.0.3",
        connected: true,
    };
    const engine = new AttackEngineService(
        {
            onNetworkReset: reset$,
            getNode: (mac: string) =>
                mac === source.mac
                    ? source
                    : mac === target.mac
                      ? target
                      : undefined,
        } as never,
        { emit() {} } as never,
        new MitigationEngineService(),
    );
    engine.rememberAttackSelection(source.mac, AttackType.DOS, target.ip);
    assert.equal(engine.launchAttack(config(AttackType.DOS)).valid, true);
    const execution = engine.activeAttacks()[0];
    assert.ok(execution.intervalHandle);
    assert.ok(execution.timeoutHandle);

    reset$.next();

    assert.equal(engine.activeAttacks().length, 0);
    assert.equal(engine.attackHistory().length, 0);
    assert.equal(engine.attackCount(), 0);
    assert.equal(engine.getLastAttackSelection(source.mac), undefined);
    assert.equal(execution.intervalHandle, undefined);
    assert.equal(execution.timeoutHandle, undefined);
    engine.ngOnDestroy();
});

test("mitigation policy covers every applicable attack type", () => {
    const policy = new MitigationPolicyService();
    const expected = new Map<AttackType, MitigationType>([
        [AttackType.DOS, MitigationType.TRAFFIC_RATE_LIMIT],
        [AttackType.MQTT_FLOOD, MitigationType.TRAFFIC_RATE_LIMIT],
        [AttackType.SENSOR_SPOOF, MitigationType.SENSOR_VALIDATION],
        [AttackType.BRUTE_FORCE, MitigationType.AUTH_RATE_LIMIT],
        [AttackType.PORT_SCAN, MitigationType.SCAN_RATE_LIMIT],
    ]);

    for (const [attackType, mitigationType] of expected) {
        const recommendations = policy.evaluate("twin-1", impactByAttack, [
            runningAttack(attackType),
        ]);
        const recommendation = recommendations.find(
            (item) => item.mitigationType === mitigationType,
        );
        assert.ok(
            recommendation,
            `${attackType} should recommend ${mitigationType}`,
        );
        const mitigation = new MitigationEngineService().applyMitigation(
            recommendation,
        );
        assert.equal(
            mitigation?.status,
            MitigationStatus.APPLIED,
            `${attackType} mitigation should apply`,
        );
    }
});

test("recovery requires an inactive attack, NORMAL anomaly, LOW impact, and five consecutive ticks", () => {
    const service = new RecoveryService();
    const mitigation = {
        id: "mit-1",
        twinId: "twin-1",
        type: MitigationType.TRAFFIC_RATE_LIMIT,
        status: MitigationStatus.APPLIED,
        relatedAttackId: "atk-1",
        createdAt: 0,
        updatedAt: 0,
    };
    const anomaly = { ...healthyAnomaly, severity: AnomalySeverity.HIGH };

    assert.equal(
        service.evaluateRecovery(mitigation, healthyAnomaly, lowImpact, true),
        RecoveryTransition.NONE,
    );
    assert.equal(
        service.evaluateRecovery(mitigation, anomaly, lowImpact, false),
        RecoveryTransition.NONE,
    );
    assert.equal(
        service.evaluateRecovery(
            mitigation,
            healthyAnomaly,
            { ...lowImpact, level: ImpactLevel.MEDIUM },
            false,
        ),
        RecoveryTransition.NONE,
    );
    assert.equal(
        service.evaluateRecovery(mitigation, healthyAnomaly, lowImpact, false),
        RecoveryTransition.VERIFYING,
    );
    mitigation.status = MitigationStatus.VERIFYING;
    for (let tick = 0; tick < 3; tick++) {
        assert.equal(
            service.evaluateRecovery(
                mitigation,
                healthyAnomaly,
                lowImpact,
                false,
            ),
            RecoveryTransition.NONE,
        );
    }
    assert.equal(
        service.evaluateRecovery(mitigation, healthyAnomaly, lowImpact, false),
        RecoveryTransition.RECOVERED,
    );

    service.cleanupForMitigation(mitigation.id);
    assert.equal(
        service.evaluateTwinRecovery(
            "twin-2",
            healthyAnomaly,
            lowImpact,
            false,
        ),
        RecoveryTransition.VERIFYING,
    );
    for (let tick = 0; tick < 3; tick++) {
        assert.equal(
            service.evaluateTwinRecovery(
                "twin-2",
                healthyAnomaly,
                lowImpact,
                false,
            ),
            RecoveryTransition.NONE,
        );
    }
    assert.equal(
        service.evaluateTwinRecovery(
            "twin-2",
            healthyAnomaly,
            lowImpact,
            false,
        ),
        RecoveryTransition.RECOVERED,
    );

    const interruptedStreak = new RecoveryService();
    assert.equal(
        interruptedStreak.evaluateTwinRecovery(
            "twin-3",
            healthyAnomaly,
            lowImpact,
            false,
        ),
        RecoveryTransition.VERIFYING,
    );
    assert.equal(
        interruptedStreak.evaluateTwinRecovery(
            "twin-3",
            healthyAnomaly,
            lowImpact,
            false,
        ),
        RecoveryTransition.NONE,
    );
    assert.equal(
        interruptedStreak.evaluateTwinRecovery(
            "twin-3",
            anomaly,
            lowImpact,
            false,
        ),
        RecoveryTransition.NONE,
        "an unhealthy observation resets the healthy streak",
    );
    assert.equal(
        interruptedStreak.evaluateTwinRecovery(
            "twin-3",
            healthyAnomaly,
            lowImpact,
            false,
        ),
        RecoveryTransition.VERIFYING,
    );
    for (let tick = 0; tick < 3; tick++) {
        assert.equal(
            interruptedStreak.evaluateTwinRecovery(
                "twin-3",
                healthyAnomaly,
                lowImpact,
                false,
            ),
            RecoveryTransition.NONE,
        );
    }
    assert.equal(
        interruptedStreak.evaluateTwinRecovery(
            "twin-3",
            healthyAnomaly,
            lowImpact,
            false,
        ),
        RecoveryTransition.RECOVERED,
    );
});

test("incident evidence retains attack, anomaly, risk, impact, mitigation, and recovery", () => {
    const correlation = new IncidentCorrelationService();
    correlation.processEvent({
        id: "twin-created",
        timestamp: new Date(),
        type: SecurityEventType.TWIN_CREATED,
        severity: SecurityEventSeverity.INFO,
        source: "00:00:00:00:00:02",
        description: "created",
        metadata: { twinId: "twin-1" },
    });
    const attackId = "attack-evidence";
    const events = [
        [
            SecurityEventType.ATTACK_STARTED,
            "00:00:00:00:00:01",
            { attackType: AttackType.DOS, intensity: 5 },
        ],
        [
            SecurityEventType.ANOMALY_DETECTED,
            "twin-1",
            { anomalyScore: 12, severity: "high" },
        ],
        [
            SecurityEventType.RISK_CHANGED,
            "twin-1",
            { currentRiskLevel: RiskLevel.HIGH, currentScore: 70, attackId },
        ],
        [
            SecurityEventType.IMPACT_CHANGED,
            "twin-1",
            {
                currentImpactLevel: ImpactLevel.MEDIUM,
                currentScore: 30,
                primaryDimension: "Performance",
                attackId,
            },
        ],
        [
            SecurityEventType.MITIGATION_RECOMMENDED,
            "twin-1",
            {
                mitigationType: MitigationType.TRAFFIC_RATE_LIMIT,
                relatedAttackId: attackId,
            },
        ],
        [
            SecurityEventType.MITIGATION_APPLIED,
            "twin-1",
            {
                mitigationType: MitigationType.TRAFFIC_RATE_LIMIT,
                mitigationId: "mit-1",
                relatedAttackId: attackId,
            },
        ],
        [
            SecurityEventType.RECOVERY_STARTED,
            "twin-1",
            {
                mitigationType: MitigationType.TRAFFIC_RATE_LIMIT,
                relatedAttackId: attackId,
            },
        ],
        [
            SecurityEventType.RECOVERY_COMPLETED,
            "twin-1",
            {
                mitigationType: MitigationType.TRAFFIC_RATE_LIMIT,
                relatedAttackId: attackId,
            },
        ],
    ] as const;

    for (const [type, source, metadata] of events) {
        correlation.processEvent({
            id: `${type}-${correlation.timelineEntries().length}`,
            timestamp: new Date(
                Date.now() + correlation.timelineEntries().length,
            ),
            type,
            source,
            target:
                type === SecurityEventType.ATTACK_STARTED
                    ? "00:00:00:00:00:02"
                    : undefined,
            severity: SecurityEventSeverity.INFO,
            description: type,
            metadata,
            relatedAttackId:
                type === SecurityEventType.ATTACK_STARTED
                    ? attackId
                    : undefined,
        });
    }

    assert.equal(correlation.incidents().length, 1);
    assert.equal(correlation.incidents()[0].status, IncidentStatus.RECOVERED);
    const categories = new Set(
        correlation.evidence().map((item) => item.category),
    );
    for (const category of [
        EvidenceCategory.ATTACK,
        EvidenceCategory.ANOMALY,
        EvidenceCategory.RISK,
        EvidenceCategory.IMPACT,
        EvidenceCategory.MITIGATION,
        EvidenceCategory.RECOVERY,
    ]) {
        assert.ok(categories.has(category), `missing ${category} evidence`);
    }
});

test("only attack launches create incidents; standalone and residual anomalies stay out of history", () => {
    const correlation = new IncidentCorrelationService();
    const targetMac = "00:00:00:00:00:02";
    correlation.processEvent({
        id: "background-anomaly-before-attack",
        timestamp: new Date(),
        type: SecurityEventType.ANOMALY_DETECTED,
        severity: SecurityEventSeverity.HIGH,
        source: "twin-1",
        description: "background anomaly",
        metadata: { severity: "high", score: 72 },
    });
    assert.equal(correlation.incidents().length, 0);

    correlation.processEvent({
        id: "twin-created-for-attack-only-incident",
        timestamp: new Date(),
        type: SecurityEventType.TWIN_CREATED,
        severity: SecurityEventSeverity.INFO,
        source: targetMac,
        description: "created",
        metadata: { twinId: "twin-1" },
    });
    correlation.processEvent({
        id: "attack-only-start",
        timestamp: new Date(),
        type: SecurityEventType.ATTACK_STARTED,
        severity: SecurityEventSeverity.HIGH,
        source: "00:00:00:00:00:01",
        target: targetMac,
        relatedAttackId: "attack-only-id",
        description: "attack started",
        metadata: { attackType: AttackType.DOS, intensity: 5 },
    });
    assert.equal(correlation.incidents().length, 1);
    const incidentId = correlation.incidents()[0].id;
    assert.equal(correlation.incidents()[0].status, IncidentStatus.INVESTIGATING);

    correlation.processEvent({
        id: "anomaly-as-attack-evidence",
        timestamp: new Date(),
        type: SecurityEventType.ANOMALY_DETECTED,
        severity: SecurityEventSeverity.HIGH,
        source: "twin-1",
        description: "attack anomaly",
        metadata: { severity: "high", score: 90 },
    });
    correlation.processEvent({
        id: "attack-only-mitigation",
        timestamp: new Date(),
        type: SecurityEventType.MITIGATION_APPLIED,
        severity: SecurityEventSeverity.MEDIUM,
        source: "twin-1",
        relatedAttackId: "attack-only-id",
        description: "mitigation applied",
        metadata: { mitigationType: MitigationType.TRAFFIC_RATE_LIMIT },
    });
    correlation.processEvent({
        id: "attack-only-recovered",
        timestamp: new Date(),
        type: SecurityEventType.RECOVERY_COMPLETED,
        severity: SecurityEventSeverity.INFO,
        source: "twin-1",
        relatedAttackId: "attack-only-id",
        description: "recovered",
        metadata: {},
    });
    assert.equal(correlation.incidents()[0].status, IncidentStatus.RECOVERED);
    assert.ok(
        correlation.evidence().some(
            (item) =>
                item.incidentId === incidentId &&
                item.category === EvidenceCategory.ANOMALY,
        ),
        "the attack anomaly is stored as evidence on its incident",
    );
    const historicalTimelineCount = correlation.timelineEntries().length;

    for (const [id, type] of [
        ["residual-anomaly-detected", SecurityEventType.ANOMALY_DETECTED],
        ["residual-anomaly-cleared", SecurityEventType.ANOMALY_CLEARED],
    ] as const) {
        correlation.processEvent({
            id,
            timestamp: new Date(),
            type,
            severity: SecurityEventSeverity.INFO,
            source: "twin-1",
            description: "residual background telemetry",
            metadata: { severity: "low", score: 5 },
        });
    }

    assert.equal(correlation.incidents().length, 1);
    assert.equal(correlation.incidents()[0].id, incidentId);
    assert.equal(correlation.incidents()[0].status, IncidentStatus.RECOVERED);
    assert.equal(correlation.timelineEntries().length, historicalTimelineCount);
});

test("concurrent attacks on one Twin keep separate incidents by execution ID", () => {
    const correlation = new IncidentCorrelationService();
    const targetMac = "00:00:00:00:00:02";
    correlation.processEvent({
        id: "twin-created",
        timestamp: new Date(),
        type: SecurityEventType.TWIN_CREATED,
        severity: SecurityEventSeverity.INFO,
        source: targetMac,
        description: "created",
        metadata: { twinId: "twin-1" },
    });
    for (const attackId of ["attack-a", "attack-b"]) {
        correlation.processEvent({
            id: `start-${attackId}`,
            timestamp: new Date(),
            type: SecurityEventType.ATTACK_STARTED,
            severity: SecurityEventSeverity.HIGH,
            source: "00:00:00:00:00:01",
            target: targetMac,
            relatedAttackId: attackId,
            description: "started",
            metadata: { attackType: AttackType.DOS, intensity: 5 },
        });
    }
    assert.equal(correlation.incidents().length, 2);
    assert.deepEqual(
        new Set(correlation.incidents().map(item => item.attackId)),
        new Set(["attack-a", "attack-b"]),
    );
    assert.equal(correlation.incidents().filter(item => item.status === IncidentStatus.INVESTIGATING).length, 2);
});

test("recovered incidents stay historical while a new attack opens a distinct incident", () => {
    const correlation = new IncidentCorrelationService();
    const twinMac = "00:00:00:00:00:02";
    correlation.processEvent({
        id: "twin-created-new-incident",
        timestamp: new Date(),
        type: SecurityEventType.TWIN_CREATED,
        severity: SecurityEventSeverity.INFO,
        source: twinMac,
        description: "created",
        metadata: { twinId: "twin-1" },
    });

    const emit = (
        id: string,
        type: SecurityEventType,
        attackId: string,
        source = "00:00:00:00:00:01",
        target?: string,
        metadata: Record<string, string | number | boolean> = {},
    ) =>
        correlation.processEvent({
            id,
            timestamp: new Date(),
            type,
            severity: SecurityEventSeverity.INFO,
            source,
            target,
            relatedAttackId: attackId,
            description: id,
            metadata,
        });

    emit(
        "attack-a-start",
        SecurityEventType.ATTACK_STARTED,
        "attack-a",
        "00:00:00:00:00:01",
        twinMac,
        {
            attackType: AttackType.DOS,
            intensity: 5,
        },
    );
    emit(
        "attack-a-mitigated",
        SecurityEventType.MITIGATION_APPLIED,
        "attack-a",
        "twin-1",
        undefined,
        {
            mitigationType: MitigationType.TRAFFIC_RATE_LIMIT,
        },
    );
    emit(
        "attack-a-recovered",
        SecurityEventType.RECOVERY_COMPLETED,
        "attack-a",
        "twin-1",
    );
    const firstIncident = correlation.incidents()[0];
    assert.equal(firstIncident.status, IncidentStatus.RECOVERED);

    // Distinct repeated delivery of an investigation event cannot reopen history.
    emit(
        "attack-a-late-start",
        SecurityEventType.ATTACK_STARTED,
        "attack-a",
        "00:00:00:00:00:01",
        twinMac,
        {
            attackType: AttackType.DOS,
            intensity: 5,
        },
    );
    assert.equal(correlation.incidents()[0].status, IncidentStatus.RECOVERED);

    // Exact duplicate event IDs are idempotent.
    emit(
        "attack-b-start",
        SecurityEventType.ATTACK_STARTED,
        "attack-b",
        "00:00:00:00:00:01",
        twinMac,
        {
            attackType: AttackType.MQTT_FLOOD,
            intensity: 5,
        },
    );
    emit(
        "attack-b-start",
        SecurityEventType.ATTACK_STARTED,
        "attack-b",
        "00:00:00:00:00:01",
        twinMac,
        {
            attackType: AttackType.MQTT_FLOOD,
            intensity: 5,
        },
    );

    // Residual risk/impact observations without a new attack/anomaly origin
    // update no historical incident and cannot create a new one on their own.
    correlation.processEvent({
        id: "residual-risk-after-recovery",
        timestamp: new Date(),
        type: SecurityEventType.RISK_CHANGED,
        severity: SecurityEventSeverity.INFO,
        source: "twin-1",
        description: "residual risk observation",
        metadata: { currentRiskLevel: RiskLevel.LOW, currentScore: 5 },
    });

    assert.equal(correlation.incidents().length, 2);
    assert.equal(correlation.incidents()[0].status, IncidentStatus.RECOVERED);
    assert.equal(correlation.incidents()[1].attackId, "attack-b");
    assert.equal(
        correlation.incidents()[1].status,
        IncidentStatus.INVESTIGATING,
    );
    assert.equal(
        correlation
            .timelineEntries()
            .filter((entry) => entry.sourceSecurityEventId === "attack-b-start")
            .length,
        1,
    );
});

test("recovery completion transitions the matching attack incident and explanation together", () => {
    const correlation = new IncidentCorrelationService();
    const events = new SecurityEventService(correlation);
    events.emit({
        type: SecurityEventType.TWIN_CREATED,
        severity: SecurityEventSeverity.INFO,
        source: "target-mac",
        description: "Twin created",
        metadata: { twinId: "twin-1" },
    });
    events.emit({
        type: SecurityEventType.ATTACK_STARTED,
        severity: SecurityEventSeverity.HIGH,
        source: "attacker-mac",
        target: "target-mac",
        relatedAttackId: "attack-guard",
        description: "Attack started",
        metadata: { attackType: AttackType.DOS, intensity: 5 },
    });
    events.emit({
        type: SecurityEventType.RECOVERY_COMPLETED,
        severity: SecurityEventSeverity.INFO,
        source: "twin-1",
        relatedAttackId: "attack-guard",
        description: "Recovery completed before a mitigation event",
        metadata: { twinId: "twin-1" },
    });

    assert.equal(
        correlation.incidents()[0].status,
        IncidentStatus.RECOVERED,
    );
    const prematureExplanation = new IncidentExplanationService().explain(
        correlation.incidents()[0],
        correlation.timelineEntries().filter(entry => entry.incidentId === correlation.incidents()[0].id),
        correlation.evidence().filter(item => item.incidentId === correlation.incidents()[0].id),
    );
    assert.match(prematureExplanation.summary, /recovery was completed/i);
    assert.doesNotMatch(prematureExplanation.summary, /being analyzed|recovery is in progress/i);
    assert.match(prematureExplanation.recoveryExplanation ?? "", /recovery completed/i);
    const recoveredExplanation = new IncidentExplanationService().explain(
        correlation.incidents()[0],
        correlation.timelineEntries().filter(entry => entry.incidentId === correlation.incidents()[0].id),
        correlation.evidence().filter(item => item.incidentId === correlation.incidents()[0].id),
    );
    assert.match(recoveredExplanation.summary, /incident recovery was completed/i);
});

test("suspicious twins may enter recovery after healthy verification begins", () => {
    assert.equal(
        isValidTransition(
            DeviceSecurityState.SUSPICIOUS,
            DeviceSecurityState.RECOVERING,
        ),
        true,
    );
    assert.equal(
        isValidTransition(
            DeviceSecurityState.RECOVERING,
            DeviceSecurityState.RECOVERED,
        ),
        true,
    );
});

test("same-twin concurrent attacks block recovery until both attacks are inactive", () => {
    const harness = createLifecycleHarness();
    try {
        const targetMac = harness.targets[0].mac;
        const twin = harness.digitalTwinService.getTwin(targetMac)!;
        const dos = harness.attacks.launchAttack(config(AttackType.DOS));
        const mqtt = harness.attacks.launchAttack(
            config(AttackType.MQTT_FLOOD),
        );
        assert.equal(dos.valid, true);
        assert.equal(mqtt.valid, true);
        const [attackA, attackB] = harness.attacks.activeAttacks();

        for (const execution of [attackA, attackB]) {
            const mitigationType = new Map<AttackType, MitigationType>([
                [AttackType.DOS, MitigationType.TRAFFIC_RATE_LIMIT],
                [AttackType.MQTT_FLOOD, MitigationType.TRAFFIC_RATE_LIMIT],
            ]).get(execution.config.type)!;
            const mitigation = harness.mitigations.applyMitigation({
                mitigationType,
                twinId: twin.id,
                relatedAttackId: execution.id,
                relatedAttackType: execution.config.type,
                reason: "concurrent recovery test",
            });
            assert.ok(mitigation);
            harness.events.emit({
                type: SecurityEventType.MITIGATION_APPLIED,
                severity: SecurityEventSeverity.MEDIUM,
                source: twin.id,
                description: `Mitigation applied: ${mitigationType}`,
                metadata: {
                    twinId: twin.id,
                    relatedAttackId: execution.id,
                    mitigationId: mitigation.id,
                    mitigationType,
                },
            });
        }

        harness.evaluate();
        assert.equal(twin.state, DeviceSecurityState.UNDER_ATTACK);

        (
            harness.attacks as unknown as {
                _completeAttack: (id: string) => void;
            }
        )._completeAttack(attackA.id);
        harness.evaluate();
        assert.equal(attackA.status, AttackStatus.COMPLETED);
        assert.equal(attackB.status, AttackStatus.RUNNING);
        assert.equal(twin.state, DeviceSecurityState.UNDER_ATTACK);

        (
            harness.attacks as unknown as {
                _completeAttack: (id: string) => void;
            }
        )._completeAttack(attackB.id);
        harness.evaluate();
        assert.equal(twin.state, DeviceSecurityState.RECOVERING);
        for (let tick = 0; tick < 4; tick++) harness.evaluate();
        assert.equal(twin.state, DeviceSecurityState.RECOVERED);
        assert.equal(harness.attacks.activeAttacks().length, 0);
        assert.ok(
            harness.correlation
                .incidents()
                .every(
                    (incident) => incident.status === IncidentStatus.RECOVERED,
                ),
            "twin-level recovery should complete each incident for attacks against that twin",
        );
    } finally {
        harness.dispose();
    }
});

test("different twins recover independently under concurrent attacks", () => {
    const harness = createLifecycleHarness(2);
    try {
        const [targetA, targetB] = harness.targets;
        const twinA = harness.digitalTwinService.getTwin(targetA.mac)!;
        const twinB = harness.digitalTwinService.getTwin(targetB.mac)!;
        const configA = {
            ...config(AttackType.DOS),
            targetNodeMac: targetA.mac,
        };
        const configB = {
            ...config(AttackType.MQTT_FLOOD),
            targetNodeMac: targetB.mac,
        };
        assert.equal(harness.attacks.launchAttack(configA).valid, true);
        assert.equal(harness.attacks.launchAttack(configB).valid, true);
        const [attackA, attackB] = harness.attacks.activeAttacks();

        harness.evaluate();
        assert.equal(twinA.state, DeviceSecurityState.UNDER_ATTACK);
        assert.equal(twinB.state, DeviceSecurityState.UNDER_ATTACK);

        (
            harness.attacks as unknown as {
                _completeAttack: (id: string) => void;
            }
        )._completeAttack(attackA.id);
        harness.evaluate();
        assert.equal(twinA.state, DeviceSecurityState.RECOVERING);
        assert.equal(twinB.state, DeviceSecurityState.UNDER_ATTACK);

        (
            harness.attacks as unknown as {
                _completeAttack: (id: string) => void;
            }
        )._completeAttack(attackB.id);
        for (let tick = 0; tick < 5; tick++) harness.evaluate();
        assert.equal(twinA.state, DeviceSecurityState.RECOVERED);
        assert.equal(twinB.state, DeviceSecurityState.RECOVERED);
    } finally {
        harness.dispose();
    }
});

test("each attack type updates its Twin and reaches verified recovery", () => {
    for (const attackType of Object.values(AttackType)) {
        const harness = createLifecycleHarness();
        try {
            const targetMac = harness.targets[0].mac;
            const twin = harness.digitalTwinService.getTwin(targetMac)!;
            const attackConfig = {
                ...config(attackType),
                targetNodeMac: targetMac,
                intensity: 1,
            };
            assert.equal(
                harness.attacks.launchAttack(attackConfig).valid,
                true,
                `${attackType} should launch`,
            );
            const execution = harness.attacks.activeAttacks()[0];
            assert.ok(
                execution,
                `${attackType} should have an active execution`,
            );

            harness.evaluate();
            assert.equal(twin.currentAttackId, execution.id);
            assert.equal(
                twin.state,
                attackType === AttackType.DOS ||
                    attackType === AttackType.MQTT_FLOOD
                    ? DeviceSecurityState.UNDER_ATTACK
                    : DeviceSecurityState.SUSPICIOUS,
            );
            assert.ok(
                twin.latestRiskAssessment,
                `${attackType} risk should be evaluated`,
            );
            assert.ok(
                twin.latestImpactAssessment,
                `${attackType} impact should be evaluated`,
            );

            (
                harness.attacks as unknown as {
                    _completeAttack: (id: string) => void;
                }
            )._completeAttack(execution.id);
            assert.equal(execution.status, AttackStatus.COMPLETED);
            harness.evaluate();
            assert.equal(twin.currentAttackId, null);
            for (let tick = 0; tick < 4; tick++) harness.evaluate();
            assert.equal(
                twin.state,
                DeviceSecurityState.RECOVERED,
                `${attackType} should recover after five healthy evaluations`,
            );
        } finally {
            harness.dispose();
        }
    }
});

test("attack completion clears the twin context and recovers after five healthy telemetry evaluations", () => {
    const reset$ = new Subject<void>();
    const added$ = new Subject<never>();
    const removed$ = new Subject<string>();
    const source = {
        mac: "00:00:00:00:00:01",
        type: NodeType.COMPUTER,
        ip: "192.168.0.2",
        connected: true,
        traffic: [] as unknown[],
        sendPacket() {},
    };
    const target = {
        mac: "00:00:00:00:00:02",
        type: NodeType.IOT,
        ip: "192.168.0.3",
        connected: true,
        traffic: [] as unknown[],
    };
    const nodes = [source, target];
    const network = {
        onNetworkReset: reset$,
        onNodeAdded: added$,
        onNodeRemoved: removed$,
        nodes,
        router: undefined,
        getNode: (mac: string) =>
            mac === source.mac
                ? source
                : mac === target.mac
                  ? target
                  : undefined,
    };
    const correlation = new IncidentCorrelationService();
    const events = new SecurityEventService(correlation);
    const attacks = new AttackEngineService(
        network as never,
        events,
        new MitigationEngineService(),
    );
    const anomaly = {
        processTelemetry: (twin: {
            id: string;
            currentAttackId: string | null;
        }) => ({
            ...healthyAnomaly,
            twinId: twin.id,
            relatedAttackId: twin.currentAttackId ?? undefined,
        }),
        cleanupTwin() {},
    } as unknown as AnomalyDetectionService;
    const mitigations = new MitigationEngineService();
    const digitalTwinService = new DigitalTwinService(
        events,
        anomaly,
        new RiskScoringService(),
        attacks,
        new ImpactAnalysisService(network as never),
        { evaluate: () => [] } as unknown as MitigationPolicyService,
        mitigations,
        new RecoveryService(),
        correlation,
        network as never,
    );
    const twin = digitalTwinService.getTwin(target.mac)!;
    const result = attacks.launchAttack({
        ...config(AttackType.DOS),
        intensity: 1,
    });
    assert.equal(result.valid, true);
    const attackId = attacks.activeAttacks()[0].id;

    const mitigation = mitigations.applyMitigation({
        mitigationType: MitigationType.TRAFFIC_RATE_LIMIT,
        twinId: twin.id,
        relatedAttackId: attackId,
        relatedAttackType: AttackType.DOS,
        reason: "attack completion recovery test",
    });
    assert.ok(mitigation);
    events.emit({
        type: SecurityEventType.MITIGATION_APPLIED,
        severity: SecurityEventSeverity.MEDIUM,
        source: twin.id,
        description: "Mitigation applied",
        metadata: {
            twinId: twin.id,
            relatedAttackId: attackId,
            mitigationId: mitigation.id,
            mitigationType: MitigationType.TRAFFIC_RATE_LIMIT,
        },
    });

    const evaluate = () =>
        (
            digitalTwinService as unknown as { _updateAllTelemetry: () => void }
        )._updateAllTelemetry();
    evaluate();
    assert.equal(twin.currentAttackId, attackId);
    assert.equal(twin.state, DeviceSecurityState.UNDER_ATTACK);
    assert.equal(
        (digitalTwinService as unknown as { _incidentDemoLifecycles: Map<string, unknown> })._incidentDemoLifecycles.size,
        1,
        "active demonstration lifecycle is tracked with the attack ID",
    );

    (
        attacks as unknown as { _completeAttack: (id: string) => void }
    )._completeAttack(attackId);
    evaluate();
    assert.equal(twin.currentAttackId, null);
    assert.equal(twin.state, DeviceSecurityState.RECOVERING);

    for (let tick = 0; tick < 3; tick++) evaluate();
    assert.equal(twin.state, DeviceSecurityState.RECOVERING);
    evaluate();
    assert.equal(twin.state, DeviceSecurityState.RECOVERED);
    assert.equal(attacks.activeAttacks().length, 0);
    assert.equal(correlation.incidents().length, 1);
    assert.equal(correlation.incidents()[0].status, IncidentStatus.RECOVERED);
    assert.ok(
        correlation
            .evidence()
            .some((e) => e.category === EvidenceCategory.RECOVERY),
    );

    const appliedMitigation = mitigations.applyMitigation({
        mitigationType: MitigationType.TRAFFIC_RATE_LIMIT,
        twinId: twin.id,
        relatedAttackId: "stale-attack",
        relatedAttackType: AttackType.DOS,
        reason: "reset cleanup test",
    });
    assert.ok(appliedMitigation);
    const resetAttack = attacks.launchAttack(config(AttackType.MQTT_FLOOD));
    assert.equal(resetAttack.valid, true);
    nodes.splice(0);
    reset$.next();
    events.reset();
    assert.equal(attacks.activeAttacks().length, 0);
    assert.equal(attacks.attackHistory().length, 0);
    assert.equal(mitigations.mitigations.length, 0);
    assert.equal(digitalTwinService.twinCount(), 0);
    assert.equal(correlation.incidents().length, 0);
    assert.equal(
        (digitalTwinService as unknown as { _incidentDemoLifecycles: Map<string, unknown> })._incidentDemoLifecycles.size,
        0,
        "network reset clears demonstration lifecycle state",
    );

    attacks.ngOnDestroy();
    digitalTwinService.ngOnDestroy();
    assert.equal(reset$.observed, false);
});

test("real pipeline completes the same mitigation lifecycle for every attack", async () => {
    const expectedMitigation = new Map<AttackType, MitigationType>([
        [AttackType.DOS, MitigationType.TRAFFIC_RATE_LIMIT],
        [AttackType.MQTT_FLOOD, MitigationType.TRAFFIC_RATE_LIMIT],
        [AttackType.SENSOR_SPOOF, MitigationType.SENSOR_VALIDATION],
        [AttackType.BRUTE_FORCE, MitigationType.AUTH_RATE_LIMIT],
        [AttackType.PORT_SCAN, MitigationType.SCAN_RATE_LIMIT],
    ]);

    for (const attackType of Object.values(AttackType)) {
        const random = Math.random;
        Math.random = () => 0.5;
        // Use the powered-device baseline so the long, accelerated recovery
        // sequence is driven by attack telemetry rather than normal battery drain.
        const harness = createLifecycleHarness(1, true, NodeType.COMPUTER);
        try {
            const targetMac = harness.targets[0].mac;
            const twin = harness.digitalTwinService.getTwin(targetMac)!;
            for (let tick = 0; tick < 12; tick++) harness.evaluate();
            const attackConfig = {
                ...config(attackType),
                targetNodeMac: targetMac,
                intensity: 5,
            };
            assert.equal(
                harness.attacks.launchAttack(attackConfig).valid,
                true,
            );
            const execution = harness.attacks.activeAttacks()[0];
            assert.ok(execution);
            assert.equal(harness.correlation.incidents().length, 1);
            assert.equal(
                harness.correlation.incidents()[0].status,
                IncidentStatus.INVESTIGATING,
                `${attackType} starts investigating`,
            );
            // Allow the existing simulated attack timer to emit at least one
            // packet batch; this makes the scan path use real PPS telemetry.
            await new Promise<void>((resolve) => setTimeout(resolve, 350));
            if (attackType === AttackType.PORT_SCAN) {
                assert.ok(
                    harness.targets[0].traffic.length > 0,
                    "port scan sends probes to the target",
                );
            }
            for (let tick = 0; tick < 4; tick++) harness.evaluate();
            const expectedDimension = new Map<AttackType, string>([
                [AttackType.DOS, "Performance"],
                [AttackType.MQTT_FLOOD, "Performance"],
                [AttackType.SENSOR_SPOOF, "Integrity"],
                [AttackType.BRUTE_FORCE, "Authentication"],
                [AttackType.PORT_SCAN, "Security / Scanning"],
            ]);
            const incident = harness.correlation
                .incidents()
                .find((item) => item.attackId === execution.id);
            assert.ok(incident, `${attackType} keeps its execution ID`);
            assert.equal(incident.attackType, attackType);
            assert.equal(
                harness.correlation
                    .incidents()
                    .filter((item) => item.attackId === execution.id).length,
                1,
                `${attackType} creates exactly one incident`,
            );

            const evidence = harness.correlation
                .evidence()
                .filter((item) => item.incidentId === incident.id);
            assert.ok(
                evidence.some(
                    (item) => item.category === EvidenceCategory.ATTACK,
                ),
            );
            assert.ok(
                evidence.some(
                    (item) => item.category === EvidenceCategory.ANOMALY,
                ),
            );
            assert.ok(
                evidence.some(
                    (item) => item.category === EvidenceCategory.RISK,
                ),
            );
            assert.ok(
                evidence.some(
                    (item) => item.category === EvidenceCategory.IMPACT,
                ),
            );
            assert.ok(
                evidence.some(
                    (item) =>
                        item.category === EvidenceCategory.IMPACT &&
                        item.impactDimensions?.includes(
                            expectedDimension.get(attackType)!,
                        ),
                ),
                `${attackType} records ${expectedDimension.get(attackType)} impact`,
            );
            assert.ok(
                evidence.some(
                    (item) => item.category === EvidenceCategory.MITIGATION,
                ),
            );
            assert.ok(
                evidence.some(
                    (item) =>
                        item.category === EvidenceCategory.MITIGATION &&
                        item.mitigationStatus === MitigationStatus.RECOMMENDED,
                ),
            );
            assert.ok(
                evidence.some(
                    (item) =>
                        item.category === EvidenceCategory.MITIGATION &&
                        item.mitigationStatus === MitigationStatus.APPLIED &&
                        item.mitigationType ===
                            expectedMitigation.get(attackType),
                ),
                `${attackType} applies ${expectedMitigation.get(attackType)}`,
            );
            const mitigationEvents = harness.events
                .events()
                .filter(
                    (event) =>
                        (event.type ===
                            SecurityEventType.MITIGATION_RECOMMENDED ||
                            event.type ===
                                SecurityEventType.MITIGATION_APPLIED) &&
                        event.metadata["relatedAttackId"] === execution.id,
                );
            assert.ok(
                mitigationEvents.some(
                    (event) =>
                        event.type === SecurityEventType.MITIGATION_RECOMMENDED,
                ),
                `${attackType} recommendation retains its attack ID`,
            );
            assert.ok(
                mitigationEvents.some(
                    (event) =>
                        event.type === SecurityEventType.MITIGATION_APPLIED,
                ),
                `${attackType} application retains its attack ID`,
            );
            assert.equal(incident.status, IncidentStatus.MITIGATED);

            (
                harness.attacks as unknown as {
                    _completeAttack: (id: string) => void;
                }
            )._completeAttack(execution.id);
            for (let tick = 0; tick < 160; tick++) {
                harness.evaluate();
                if (
                    harness.correlation
                        .incidents()
                        .find((item) => item.id === incident.id)?.status ===
                    IncidentStatus.RECOVERED
                )
                    break;
            }

            const recoveredIncident = harness.correlation
                .incidents()
                .find((item) => item.id === incident.id);
            assert.equal(
                recoveredIncident?.status,
                IncidentStatus.RECOVERED,
                `${attackType} incident must complete recovery (state=${twin.state}, impact=${twin.latestImpactAssessment?.level}, loss=${twin.telemetry.packetLoss}, anomaly=${JSON.stringify((harness.digitalTwinService as any).anomalyDetection.processTelemetry(twin))}, recoveryEvents=${harness.events
                    .events()
                    .filter((e) => e.type.startsWith("recovery"))
                    .map((e) => e.type)
                    .join(",")})`,
            );
            assert.equal(
                twin.state,
                DeviceSecurityState.RECOVERED,
                `${attackType} Twin recovers`,
            );
            assert.ok(
                harness.correlation
                    .evidence()
                    .some(
                        (item) =>
                            item.incidentId === incident.id &&
                            item.category === EvidenceCategory.RECOVERY,
                    ),
            );
            assert.ok(
                harness.correlation
                    .timelineEntries()
                    .some(
                        (entry) =>
                            entry.incidentId === incident.id &&
                            entry.eventType ===
                                SecurityEventType.MITIGATION_APPLIED,
                    ),
            );
            assert.ok(
                harness.correlation
                    .timelineEntries()
                    .some(
                        (entry) =>
                            entry.incidentId === incident.id &&
                            entry.eventType ===
                                SecurityEventType.RECOVERY_STARTED,
                    ),
            );
            assert.ok(
                harness.correlation
                    .timelineEntries()
                    .some(
                        (entry) =>
                            entry.incidentId === incident.id &&
                            entry.eventType ===
                                SecurityEventType.RECOVERY_COMPLETED,
                    ),
            );
        } finally {
            harness.dispose();
            Math.random = random;
        }
    }
});

test("timed incident demonstration reaches RECOVERED for all five real attack services within 12 seconds", async () => {
    const expectedMitigation = new Map<AttackType, MitigationType>([
        [AttackType.DOS, MitigationType.TRAFFIC_RATE_LIMIT],
        [AttackType.MQTT_FLOOD, MitigationType.TRAFFIC_RATE_LIMIT],
        [AttackType.SENSOR_SPOOF, MitigationType.SENSOR_VALIDATION],
        [AttackType.BRUTE_FORCE, MitigationType.AUTH_RATE_LIMIT],
        [AttackType.PORT_SCAN, MitigationType.SCAN_RATE_LIMIT],
    ]);
    const originalRandom = Math.random;
    Math.random = () => 0;

    try {
        for (const attackType of Object.values(AttackType)) {
            const harness = createLifecycleHarness(1, true, NodeType.COMPUTER);
            try {
                const targetMac = harness.targets[0].mac;
                const twin = harness.digitalTwinService.getTwin(targetMac)!;
                for (let tick = 0; tick < 12; tick++) harness.evaluate();

                const launchedAt = Date.now();
                assert.equal(
                    harness.attacks.launchAttack({
                        ...config(attackType),
                        targetNodeMac: targetMac,
                    }).valid,
                    true,
                );
                const execution = harness.attacks.activeAttacks()[0];
                const initialIncident = harness.correlation.incidents().find(
                    incident => incident.attackId === execution.id,
                );
                assert.ok(initialIncident);
                assert.equal(initialIncident.status, IncidentStatus.INVESTIGATING);
                assert.equal(
                    harness.correlation.incidents().filter(incident => incident.attackId === execution.id).length,
                    1,
                );

                const connection = {
                    node1: { mac: "00:00:00:00:00:01" },
                    node2: { mac: targetMac },
                } as Connection;
                assert.equal(
                    isConnectionUnderActiveAttack(connection, harness.attacks.activeAttacks(), harness.events.events()),
                    true,
                    `${attackType} begins with an animated attack connection`,
                );

                const deadline = launchedAt + 12_500;
                while (Date.now() < deadline) {
                    const incident = harness.correlation.incidents().find(
                        item => item.attackId === execution.id,
                    );
                    if (incident?.status === IncidentStatus.RECOVERED) break;
                    await new Promise<void>(resolve => setTimeout(resolve, 50));
                }

                const incident = harness.correlation.incidents().find(
                    item => item.attackId === execution.id,
                );
                const elapsedMs = Date.now() - launchedAt;
                assert.equal(incident?.status, IncidentStatus.RECOVERED, `${attackType} lifecycle`);
                assert.ok(elapsedMs <= 12_500, `${attackType} took ${elapsedMs} ms`);
                assert.equal(
                    harness.correlation.incidents().filter(item => item.attackId === execution.id).length,
                    1,
                    `${attackType} keeps one incident per execution`,
                );
                assert.deepEqual(
                    getIncidentLifecycleProgress(incident!.status),
                    { investigating: "completed", mitigated: "completed", recovered: "completed" },
                    `${attackType} shows all lifecycle stages completed`,
                );
                assert.equal(
                    harness.mitigations.mitigations.find(item => item.relatedAttackId === execution.id)?.type,
                    expectedMitigation.get(attackType),
                );
                for (const eventType of [
                    SecurityEventType.MITIGATION_RECOMMENDED,
                    SecurityEventType.MITIGATION_APPLIED,
                    SecurityEventType.RECOVERY_STARTED,
                    SecurityEventType.RECOVERY_COMPLETED,
                ]) {
                    assert.ok(
                        harness.events.events().some(
                            event => event.type === eventType && event.relatedAttackId === execution.id,
                        ),
                        `${attackType} emits ${eventType} for its execution ID`,
                    );
                }
                const timelineTypes = harness.correlation.timelineEntries()
                    .filter(entry => entry.incidentId === incident!.id)
                    .map(entry => entry.eventType);
                const lifecycleEventIndexes = [
                    SecurityEventType.MITIGATION_RECOMMENDED,
                    SecurityEventType.MITIGATION_APPLIED,
                    SecurityEventType.RECOVERY_STARTED,
                    SecurityEventType.RECOVERY_COMPLETED,
                ].map(eventType => timelineTypes.indexOf(eventType));
                assert.ok(lifecycleEventIndexes.every(index => index >= 0));
                assert.deepEqual(lifecycleEventIndexes, [...lifecycleEventIndexes].sort((a, b) => a - b));
                assert.equal(
                    isConnectionUnderActiveAttack(connection, harness.attacks.activeAttacks(), harness.events.events()),
                    false,
                    `${attackType} connection stays solid after mitigation and recovery`,
                );
                assert.ok(twin, `${attackType} retains its Digital Twin`);
            } finally {
                harness.dispose();
            }
        }
    } finally {
        Math.random = originalRandom;
    }
});
