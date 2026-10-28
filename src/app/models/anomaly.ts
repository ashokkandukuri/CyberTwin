/**
 * Severity levels for anomaly detection based on Z-score thresholds.
 */
export enum AnomalySeverity {
    NORMAL = "normal",
    LOW = "low",
    MEDIUM = "medium",
    HIGH = "high",
    CRITICAL = "critical",
}

export const ANOMALY_THRESHOLDS = {
    LOW: 3.0,
    MEDIUM: 5.0,
    HIGH: 7.0,
    CRITICAL: 10.0,
};

export function getAnomalySeverity(zScore: number): AnomalySeverity {
    if (zScore >= ANOMALY_THRESHOLDS.CRITICAL) return AnomalySeverity.CRITICAL;
    if (zScore >= ANOMALY_THRESHOLDS.HIGH) return AnomalySeverity.HIGH;
    if (zScore >= ANOMALY_THRESHOLDS.MEDIUM) return AnomalySeverity.MEDIUM;
    if (zScore >= ANOMALY_THRESHOLDS.LOW) return AnomalySeverity.LOW;
    return AnomalySeverity.NORMAL;
}

/**
 * Extracted features specifically used for anomaly tracking.
 */
export enum AnomalyFeature {
    CPU = "cpuUtilization",
    MEMORY = "memoryUtilization",
    PPS = "packetsPerSecond",
    BANDWIDTH = "bandwidthUsage",
    LATENCY = "latency",
    PACKET_LOSS = "packetLoss",
    CONNECTIONS = "connectionCount",
    TEMPERATURE = "temperature",
    BATTERY = "batteryLevel",
    AUTH_FAILURES_RATE = "authFailuresRate", // Derived delta
    SENSOR = "sensorReading",
}

/**
 * Strongly typed anomaly score per feature.
 */
export interface FeatureZScore {
    readonly feature: AnomalyFeature;
    readonly value: number;
    readonly expected: number;
    readonly zScore: number;
}

/**
 * Result of scoring a telemetry observation against the baseline.
 */
export interface AnomalyResult {
    readonly twinId: string;
    readonly timestamp: Date;
    readonly isArmed: boolean;
    readonly score: number; // The composite max Z-score
    readonly severity: AnomalySeverity;
    readonly maxFeature?: AnomalyFeature;
    readonly featureDetails: readonly FeatureZScore[];
    readonly relatedAttackId?: string | null;
}

/**
 * Minimum variance strictly enforced to prevent Division-by-Zero
 * or Infinite Z-scores when a feature remains perfectly flat.
 */
export const MIN_VARIANCE_EPSILON = 1e-6;

/**
 * A deterministic Exponentially Weighted Moving Average (EWMA) and Variance (EWMVar) model.
 * Bounded O(1) memory, tracks a single continuous variable.
 */
export class EwmaModel {
    private _mean: number = 0;
    private _variance: number = 0;
    private _count: number = 0;

    constructor(
        public readonly alpha: number = 0.1,
        public readonly minSamples: number = 10
    ) {}

    public get mean(): number { return this._mean; }
    public get variance(): number { return this._variance; }
    public get count(): number { return this._count; }
    public get isWarm(): boolean { return this._count >= this.minSamples; }

    /**
     * Calculates the Z-score for a given value AGAINST the CURRENT baseline.
     * Does not mutate the baseline.
     */
    public getZScore(value: number): number {
        if (!this.isWarm || !Number.isFinite(value)) {
            return 0; // Not armed or invalid
        }
        const stdDev = Math.sqrt(Math.max(this._variance, MIN_VARIANCE_EPSILON));
        return Math.abs(value - this._mean) / stdDev;
    }

    /**
     * Observes a new value and strictly integrates it into the baseline.
     * Rejects NaN/Infinity safely.
     */
    public observe(value: number): void {
        if (!Number.isFinite(value)) {
            return;
        }
        
        if (this._count === 0) {
            this._mean = value;
            this._variance = 0;
        } else {
            const diff = value - this._mean;
            this._mean = this._mean + this.alpha * diff;
            // EWMVar formula: var = (1 - alpha) * var + alpha * diff^2
            this._variance = (1 - this.alpha) * this._variance + (this.alpha * diff * diff);
        }
        
        this._variance = Math.max(0, this._variance); // Guarantee non-negative variance
        this._count++;
    }
}

/**
 * Represents the isolated anomaly detection state per Digital Twin.
 * Supports independently updating and scoring features, computing deltas,
 * and selectively freezing baselines.
 */
export class TwinBaseline {
    private readonly _models = new Map<AnomalyFeature, EwmaModel>();
    private _lastAuthFailures: number | null = null;
    
    // Checkpoint 4 state tracking
    public previousSeverity: AnomalySeverity = AnomalySeverity.NORMAL;
    public clearStreak: number = 0;
    
    constructor(
        public readonly alpha: number = 0.1, 
        public readonly minSamples: number = 10
    ) {
        for (const feature of Object.values(AnomalyFeature)) {
            this._models.set(feature, new EwmaModel(alpha, minSamples));
        }
    }

    public getModel(feature: AnomalyFeature): EwmaModel | undefined {
        return this._models.get(feature);
    }

    public get isFullyWarm(): boolean {
        for (const model of this._models.values()) {
            if (!model.isWarm) return false;
        }
        return true;
    }

    /**
     * Computes the rate/delta of auth failures.
     * Guards against resets and invalid counts.
     */
    public calculateDeltaAuth(currentAuthFailures: number): number {
        if (!Number.isFinite(currentAuthFailures) || currentAuthFailures < 0) {
            return 0;
        }
        
        let delta = 0;
        if (this._lastAuthFailures !== null) {
            delta = currentAuthFailures - this._lastAuthFailures;
            if (delta < 0) {
                // If the counter drops, treat the new count as the delta (a reset occurred)
                delta = currentAuthFailures;
            }
        } else {
            // First observation shouldn't spike, just track
            delta = 0;
        }
        
        return delta;
    }

    /**
     * Commits the raw cumulative auth failures for future deltas.
     */
    public updateLastAuth(currentAuthFailures: number): void {
         if (Number.isFinite(currentAuthFailures) && currentAuthFailures >= 0) {
             this._lastAuthFailures = currentAuthFailures;
         }
    }

    /**
     * Observes values for an explicit feature.
     */
    public observeFeature(feature: AnomalyFeature, value: number): void {
        const model = this._models.get(feature);
        if (model) {
            model.observe(value);
        }
    }

    /**
     * Calculates the Z-score for an explicit feature WITHOUT contaminating the baseline.
     */
    public scoreFeature(feature: AnomalyFeature, value: number): number {
        const model = this._models.get(feature);
        if (model) {
            return model.getZScore(value);
        }
        return 0;
    }
}
