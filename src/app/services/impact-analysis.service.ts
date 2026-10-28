import { Injectable } from "@angular/core";
import { TwinTelemetry } from "@models/telemetry";
import { AnomalyResult, AnomalyFeature } from "@models/anomaly";
import { ImpactAssessment, ImpactLevel } from "@models/impact";
import { NetworkService } from "@services/network.service";
import { NodeType } from "@models/node";
import { Router } from "@models/router";
import { AttackExecution } from "@models/attack-execution";
import { AttackType, SensorSpoofParameters } from "@models/attack-types";

@Injectable({ providedIn: "root" })
export class ImpactAnalysisService {
    
    constructor(private readonly networkService: NetworkService) {}
    
    public evaluateImpact(
        twinId: string,
        nodeMac: string,
        telemetry: TwinTelemetry,
        anomaly: AnomalyResult,
        attack?: AttackExecution | null,
    ): ImpactAssessment {
        const performanceImpact = this._calculatePerformance(telemetry);
        const integrityImpact = this._calculateIntegrity(anomaly, attack);
        const authenticationImpact = this._calculateAuthentication(anomaly);
        const securityImpact = this._calculateSecurity(anomaly, attack);

        const overallScore = this._clamp(
            performanceImpact + integrityImpact + authenticationImpact + securityImpact,
            0,
            100,
        );
        
        return {
            twinId,
            timestamp: Date.now(),
            overallScore,
            level: this._determineLevel(overallScore),
            performanceImpact,
            integrityImpact,
            authenticationImpact,
            securityImpact,
            potentialBlastRadius: this._calculateBlastRadius(nodeMac),
            primaryImpactDimension: this._determinePrimary(
                performanceImpact,
                integrityImpact,
                authenticationImpact,
                securityImpact,
            ),
        };
    }

    private _calculateBlastRadius(nodeMac: string): number {
        // ImpactAssessment is keyed by Digital Twin ID, while NetworkService is keyed
        // by the stable node MAC. The caller passes the twin ID only, so resolve the
        // node by scanning the small simulated network rather than assuming the UUID
        // is a MAC address.
        const targetNode = this.networkService.getNode(nodeMac);
        
        // 1. If the target node is NOT a Router/Gateway: return 0
        if (!targetNode || !NodeType.RouterTypes.includes(targetNode.type)) {
            return 0;
        }

        // 2. If the target is a Router/Gateway: start at 20
        let score = 20;
        
        const router = targetNode as Router;
        // Inspect the flat NetworkService connections collection once
        const connections = router.connections || [];
        
        // Count connected ACTIVE endpoints belonging to that router
        let activeEndpoints = 0;
        const seenEndpoints = new Set<string>();

        for (const conn of connections) {
            // Determine the remote endpoint safely
            const endpoint = conn.node1.mac === nodeMac ? conn.node2 : conn.node1;
            
            // Check if endpoint exists, is not the router itself, and is active (connected)
            if (endpoint && endpoint.mac !== nodeMac && endpoint.connected) {
                // Deduplicate to avoid double-counting if logical connections expose both directions
                if (!seenEndpoints.has(endpoint.mac)) {
                    seenEndpoints.add(endpoint.mac);
                    activeEndpoints++;
                }
            }
        }
        
        // Add 10 for each qualifying active endpoint
        score += activeEndpoints * 10;
        
        // Clamp result to 0-100
        return this._clamp(score, 0, 100);
    }

    private _clamp(value: number, min: number, max: number): number {
        if (typeof value !== "number" || !Number.isFinite(value)) {
            return 0; // Invalid numeric values must contribute 0
        }
        return Math.min(Math.max(value, min), max);
    }

    private _calculatePerformance(telemetry: TwinTelemetry): number {
        const cpu = this._clamp((telemetry.cpuUtilization - 80) / 20, 0, 1) * 10;
        const mem = this._clamp((telemetry.memoryUtilization - 80) / 20, 0, 1) * 5;
        const lat = this._clamp((telemetry.latency - 100) / 900, 0, 1) * 10;
        const loss = this._clamp(telemetry.packetLoss / 50, 0, 1) * 15;

        // Ensure final result is finite and bounded
        return this._clamp(cpu + mem + lat + loss, 0, 40);
    }

    private _calculateIntegrity(
        anomaly: AnomalyResult,
        attack?: AttackExecution | null,
    ): number {
        const spoofField = attack?.config.type === AttackType.SENSOR_SPOOF
            ? (attack.config.parameters as SensorSpoofParameters).targetField
            : undefined;
        const spoofFeature = spoofField === "sensorReading"
            ? AnomalyFeature.SENSOR
            : spoofField as AnomalyFeature | undefined;
        const feature = anomaly.featureDetails.find(f =>
            f.feature === (spoofFeature ?? AnomalyFeature.SENSOR),
        );
        const zScore = feature ? feature.zScore : 0;
        return this._clamp(zScore / 10, 0, 1) * 30;
    }

    private _calculateAuthentication(anomaly: AnomalyResult): number {
        const feature = anomaly.featureDetails.find(f => f.feature === AnomalyFeature.AUTH_FAILURES_RATE);
        const zScore = feature ? feature.zScore : 0;
        return this._clamp(zScore / 10, 0, 1) * 30;
    }

    private _calculateSecurity(
        anomaly: AnomalyResult,
        attack?: AttackExecution | null,
    ): number {
        if (attack?.config.type !== AttackType.PORT_SCAN) return 0;
        const feature = anomaly.featureDetails.find(f => f.feature === AnomalyFeature.PPS);
        const zScore = feature ? feature.zScore : 0;
        return this._clamp(zScore / 10, 0, 1) * 30;
    }

    private _determineLevel(score: number): ImpactLevel {
        if (score >= 80) return ImpactLevel.CRITICAL;
        if (score >= 50) return ImpactLevel.HIGH;
        if (score >= 20) return ImpactLevel.MEDIUM;
        return ImpactLevel.LOW;
    }

    private _determinePrimary(perf: number, integ: number, auth: number, security: number): string {
        if (perf === 0 && integ === 0 && auth === 0 && security === 0) return "None";
        
        // Deterministic tie-breaking priority: Performance > Integrity > Authentication > Security
        if (perf >= integ && perf >= auth && perf >= security) return "Performance";
        if (integ >= auth && integ >= security) return "Integrity";
        if (auth >= security) return "Authentication";
        return "Security / Scanning";
    }
}
