import { Injectable } from "@angular/core";
import { DigitalTwin } from "@models/digital-twin";
import { 
    TwinBaseline, 
    AnomalyResult, 
    AnomalyFeature, 
    FeatureZScore, 
    getAnomalySeverity, 
    AnomalySeverity 
} from "@models/anomaly";

/**
 * Service responsible for deterministic anomaly detection logic.
 * Correlates DigitalTwin telemetry snapshots with EWMA baselines.
 */
const MAX_FEATURE_Z_SCORE = 20;

@Injectable({ providedIn: "root" })
export class AnomalyDetectionService {
    private readonly _baselines = new Map<string, TwinBaseline>();

    /**
     * Cleans up the baseline memory for a removed Digital Twin.
     */
    public cleanupTwin(twinId: string): void {
        this._baselines.delete(twinId);
    }

    /**
     * Processes a single telemetry snapshot for a twin.
     * Evaluates anomalies before optionally updating the baseline.
     */
    public processTelemetry(twin: DigitalTwin): AnomalyResult {
        let baseline = this._baselines.get(twin.id);
        if (!baseline) {
            baseline = new TwinBaseline();
            this._baselines.set(twin.id, baseline);
        }

        const telemetry = twin.telemetry;
        
        // 1. Extract features & calculate tick derivatives
        const deltaAuth = baseline.calculateDeltaAuth(telemetry.authFailures);

        const currentValues: Record<AnomalyFeature, number> = {
            [AnomalyFeature.CPU]: telemetry.cpuUtilization,
            [AnomalyFeature.MEMORY]: telemetry.memoryUtilization,
            [AnomalyFeature.PPS]: telemetry.packetsPerSecond,
            [AnomalyFeature.BANDWIDTH]: telemetry.bandwidthUsage,
            [AnomalyFeature.LATENCY]: telemetry.latency,
            [AnomalyFeature.PACKET_LOSS]: telemetry.packetLoss,
            [AnomalyFeature.CONNECTIONS]: telemetry.connectionCount,
            [AnomalyFeature.TEMPERATURE]: telemetry.temperature,
            [AnomalyFeature.BATTERY]: telemetry.batteryLevel,
            [AnomalyFeature.AUTH_FAILURES_RATE]: deltaAuth,
            [AnomalyFeature.SENSOR]: telemetry.sensorReading,
        };

        const isArmed = baseline.isFullyWarm;
        let maxScore = 0;
        let dominantFeature: AnomalyFeature | undefined = undefined;
        const featureDetails: FeatureZScore[] = [];

        // 2. Score feature deviations against existing baseline
        for (const feature of Object.values(AnomalyFeature)) {
            const val = currentValues[feature];
            const model = baseline.getModel(feature);
            
            // A raw Z-score can become numerically enormous when a telemetry feature
            // is normally near zero (for example bandwidth) and an attack suddenly
            // produces traffic. Keep the detector deterministic and bounded while
            // preserving all configured severity thresholds (3/5/7/10).
            const zScore = Math.min(MAX_FEATURE_Z_SCORE, Math.max(0, baseline.scoreFeature(feature, val)));
            
            if (model && isArmed) {
                featureDetails.push({
                    feature,
                    value: val,
                    expected: model.mean,
                    zScore
                });

                if (zScore > maxScore) {
                    maxScore = zScore;
                    dominantFeature = feature;
                }
            } else if (model) {
                featureDetails.push({
                    feature,
                    value: val,
                    expected: model.mean,
                    zScore: 0
                });
            }
        }

        const severity = isArmed ? getAnomalySeverity(maxScore) : AnomalySeverity.NORMAL;
        const isAnomalous = severity !== AnomalySeverity.NORMAL;
        
        // 3. Update tick derivatives (MUST happen even if EWMA is frozen to compute clean deltas per tick)
        baseline.updateLastAuth(telemetry.authFailures);

        // 4. Freeze or update EWMA Baseline
        const hasActiveAttack = twin.currentAttackId !== null && twin.currentAttackId !== undefined;
        const shouldFreeze = isAnomalous || hasActiveAttack;

        if (!shouldFreeze) {
            for (const feature of Object.values(AnomalyFeature)) {
                baseline.observeFeature(feature, currentValues[feature]);
            }
        }

        // 5. Return Result
        return {
            twinId: twin.id,
            timestamp: new Date(),
            isArmed,
            score: maxScore,
            severity,
            maxFeature: dominantFeature,
            featureDetails,
            relatedAttackId: twin.currentAttackId
        };
    }
}
