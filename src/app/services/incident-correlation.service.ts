import { Injectable, signal, Signal, WritableSignal } from "@angular/core";
import { SecurityEvent, SecurityEventType } from "@models/security-event";
import { Incident, IncidentStatus } from "@models/incident";
import { IncidentTimelineEntry } from "@models/incident-timeline-entry";
import { IncidentEvidence, EvidenceCategory } from "@models/incident-evidence";
import { RiskLevel } from "@models/risk";
import { ImpactLevel } from "@models/impact";
import { AttackType } from "@models/attack-types";
import { MitigationType, MitigationStatus } from "@models/mitigation";
import { AnomalySeverity } from "@models/anomaly";

function generateId(): string {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
        return crypto.randomUUID();
    }
    return `inc-${Date.now()}-${Math.floor(Math.random() * 1000000)}`;
}

@Injectable({ providedIn: "root" })
export class IncidentCorrelationService {
    private readonly _incidents: WritableSignal<Incident[]> = signal([]);
    private readonly _timelineEntries: WritableSignal<IncidentTimelineEntry[]> = signal([]);
    private readonly _evidence: WritableSignal<IncidentEvidence[]> = signal([]);

    public readonly incidents: Signal<Incident[]> = this._incidents.asReadonly();
    public readonly timelineEntries: Signal<IncidentTimelineEntry[]> = this._timelineEntries.asReadonly();
    public readonly evidence: Signal<IncidentEvidence[]> = this._evidence.asReadonly();

    // Indexes for duplicate protection
    private processedEventKeys = new Set<string>();
    /** Stable mapping from node MAC addresses to Digital Twin IDs. */
    private readonly twinIdByMac = new Map<string, string>();

    public getLatestIncidentForTwin(twinId: string): Incident | null {
        const incidents = this._incidents().filter(i => i.twinId === twinId);
        if (incidents.length === 0) return null;
        
        // Prefer active over historical
        const active = incidents.filter(i => i.status !== IncidentStatus.CLOSED && i.status !== IncidentStatus.RECOVERED);
        if (active.length > 0) {
            return active.sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime())[0];
        }
        
        // Fallback to latest historical
        return incidents.sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime())[0];
    }

    /**
     * Resolves an attack execution ID from either the typed event field or
     * metadata emitted by risk/impact/mitigation stages.
     * The literal "None" is treated as absence, not as a real attack ID.
     */
    private getEventAttackId(event: SecurityEvent): string | undefined {
        const candidates = [
            event.relatedAttackId,
            event.metadata["relatedAttackId"] as string | undefined,
            event.metadata["attackId"] as string | undefined,
        ];
        const attackId = candidates.find(value => typeof value === "string" && value.length > 0 && value !== "None");
        return attackId;
    }

    /**
     * Returns the Digital Twin that an incident is about.
     * Attack lifecycle events use the target device as the incident subject;
     * all other security events originate from the affected Twin itself.
     */
    private getIncidentTwinId(event: SecurityEvent): string {
        switch (event.type) {
            case SecurityEventType.ATTACK_STARTED:
            case SecurityEventType.ATTACK_PROGRESS:
            case SecurityEventType.ATTACK_DETECTED:
            case SecurityEventType.ATTACK_STOPPED:
            case SecurityEventType.ATTACK_FAILED:
            case SecurityEventType.ATTACK_COMPLETED:
                if (event.target) {
                    return this.twinIdByMac.get(event.target) ?? event.target;
                }
                return event.source;
            default:
                // Risk/impact/anomaly events use the Digital Twin ID as source.
                return event.source;
        }
    }

    private isIncidentRelevantEvent(type: SecurityEventType): boolean {
        switch (type) {
            case SecurityEventType.ANOMALY_DETECTED:
            case SecurityEventType.ANOMALY_CLEARED:
            case SecurityEventType.ATTACK_STARTED:
            case SecurityEventType.ATTACK_PROGRESS:
            case SecurityEventType.ATTACK_DETECTED:
            case SecurityEventType.ATTACK_STOPPED:
            case SecurityEventType.ATTACK_FAILED:
            case SecurityEventType.ATTACK_COMPLETED:
            case SecurityEventType.DEVICE_DEGRADED:
            case SecurityEventType.DEVICE_COMPROMISED:
            case SecurityEventType.MITIGATION_RECOMMENDED:
            case SecurityEventType.MITIGATION_APPLIED:
            case SecurityEventType.MITIGATION_STOPPED:
            case SecurityEventType.RECOVERY_STARTED:
            case SecurityEventType.RECOVERY_COMPLETED:
            case SecurityEventType.RECOVERY_FAILED:
            case SecurityEventType.RISK_CHANGED:
            case SecurityEventType.IMPACT_CHANGED:
                return true;
            default:
                return false;
        }
    }

    public processEvent(event: SecurityEvent): void {
        // Twin lifecycle/state bookkeeping is not itself a security incident.
        // Keep the mapping so later attack/risk/impact events use the same Twin identity.
        if (event.type === SecurityEventType.TWIN_CREATED) {
            const twinId = event.metadata["twinId"];
            if (typeof twinId === "string" && twinId.length > 0) {
                this.twinIdByMac.set(event.source, twinId);
            }
            return;
        }
        if (event.type === SecurityEventType.TWIN_REMOVED) {
            this.twinIdByMac.delete(event.source);
            return;
        }
        if (!this.isIncidentRelevantEvent(event.type)) {
            return;
        }

        // Idempotency: Duplicate Protection
        const dedupKey = event.id || [
            event.type,
            event.source,
            event.timestamp.getTime(),
            event.relatedAttackId || 'no-atk'
        ].join('-');
        
        if (this.processedEventKeys.has(dedupKey)) {
            return;
        }
        this.processedEventKeys.add(dedupKey);

        let incident = this.correlateEvent(event);

        // Only an identified simulated attack may open a brand-new incident.
        // Anomaly, risk, impact, mitigation, and recovery events are evidence or
        // lifecycle updates for an active attack incident; on their own they are
        // never security incidents. This also keeps residual telemetry out of
        // recovered incident history.
        if (!incident) {
            if (!this.canCreateIncident(event)) {
                return;
            }
            // One execution ID identifies one simulated attack. Late lifecycle events
            // must not turn that attack's recovered/closed history into a new incident.
            const attackId = this.getEventAttackId(event);
            const hasTerminalAttackIncident = attackId !== undefined && this._incidents().some(i =>
                i.attackId === attackId &&
                (i.status === IncidentStatus.RECOVERED || i.status === IncidentStatus.CLOSED)
            );
            if (hasTerminalAttackIncident) {
                return;
            }
            incident = this.createIncident(event);
        }

        // Add timeline entry
        const timelineEntry = this.createTimelineEntry(incident.id, event);
        this._timelineEntries.update(entries => [...entries, timelineEntry]);

        // Add evidence if applicable
        const evidence = this.createEvidence(incident.id, event);
        if (evidence) {
            this._evidence.update(evs => [...evs, evidence]);
        }

        // Update incident state
        this.updateIncident(incident, event, timelineEntry, evidence);
    }

    private canCreateIncident(event: SecurityEvent): boolean {
        switch (event.type) {
            case SecurityEventType.ATTACK_STARTED:
            case SecurityEventType.ATTACK_DETECTED:
                return this.getEventAttackId(event) !== undefined;
            default:
                return false;
        }
    }

    private correlateEvent(event: SecurityEvent): Incident | null {
        const incidents = this._incidents();
        const attackId = this.getEventAttackId(event);
        
        if (attackId) {
            // An execution ID always resolves to its owning incident, including
            // historical incidents. Never reopen history for a late event.
            const byAttack = incidents.find(i => i.attackId === attackId);
            if (byAttack) {
                return byAttack.status === IncidentStatus.CLOSED || byAttack.status === IncidentStatus.RECOVERED
                    ? null
                    : byAttack;
            }

            // A different execution ID always represents a different attack
            // incident, even when another attack against this Twin is active.
            return null;
        }

        // 3. No attack ID in event -> fallback to the most recent active incident for the Twin
        const twinId = this.getIncidentTwinId(event);
        return this.getActiveIncidentForTwin(twinId);
    }

    private getActiveIncidentForTwin(twinId: string): Incident | null {
        return this._incidents()
            .filter(i => i.twinId === twinId && i.status !== IncidentStatus.CLOSED && i.status !== IncidentStatus.RECOVERED)
            .sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime())[0] ?? null;
    }

    private createIncident(event: SecurityEvent): Incident {
        const attackId = this.getEventAttackId(event);
        const incident: Incident = {
            id: generateId(),
            twinId: this.getIncidentTwinId(event),
            createdAt: event.timestamp,
            updatedAt: event.timestamp,
            status: IncidentStatus.OPEN,
            title: `Incident on ${this.getIncidentTwinId(event)}`,
            timelineEntryIds: [],
            evidenceIds: [],
            attackId: attackId,
            attackType: event.metadata['attackType'] as AttackType | undefined
        };

        this._incidents.update(list => [...list, incident]);
        return incident;
    }

    private createTimelineEntry(incidentId: string, event: SecurityEvent): IncidentTimelineEntry {
        return {
            id: generateId(),
            incidentId,
            timestamp: event.timestamp,
            eventType: event.type,
            title: event.type,
            summary: event.description,
            sourceSecurityEventId: event.id,
            metadata: { ...event.metadata }
        };
    }

    private createEvidence(incidentId: string, event: SecurityEvent): IncidentEvidence | null {
        const meta = event.metadata;
        const id = generateId();
        const timestamp = event.timestamp;
        
        switch (event.type) {
            case SecurityEventType.ANOMALY_DETECTED:
            case SecurityEventType.ANOMALY_CLEARED:
                if (meta['severity'] || meta['anomalySeverity'] || meta['score'] !== undefined || meta['anomalyScore'] !== undefined) {
                    return {
                        id, incidentId, timestamp,
                        category: EvidenceCategory.ANOMALY,
                        description: `Anomaly evaluation: ${meta['severity'] || meta['anomalySeverity'] || event.severity || 'N/A'}`,
                        anomalySeverity: meta['severity'] as AnomalySeverity,
                        anomalyScore: this.safeNum(meta['score'] ?? meta['anomalyScore'])
                    };
                }
                break;
            case SecurityEventType.RISK_CHANGED:
                if (meta['level'] || meta['currentRiskLevel'] || meta['score'] !== undefined || meta['currentScore'] !== undefined) {
                    return {
                        id, incidentId, timestamp,
                        category: EvidenceCategory.RISK,
                        description: `Risk updated to ${meta['level'] || meta['currentRiskLevel'] || 'N/A'}`,
                        riskLevel: (meta['level'] ?? meta['currentRiskLevel']) as RiskLevel,
                        riskScore: this.safeNum(meta['score'] ?? meta['currentScore']),
                        riskFactors: meta['primaryFactor'] ? [meta['primaryFactor'] as string] : undefined
                    };
                }
                break;
            case SecurityEventType.IMPACT_CHANGED:
                if (meta['level'] || meta['currentImpactLevel'] || meta['overallScore'] !== undefined || meta['currentScore'] !== undefined) {
                    return {
                        id, incidentId, timestamp,
                        category: EvidenceCategory.IMPACT,
                        description: `Impact updated to ${meta['level'] || meta['currentImpactLevel'] || 'N/A'}`,
                        impactLevel: (meta['level'] ?? meta['currentImpactLevel']) as ImpactLevel,
                        impactScore: this.safeNum(meta['overallScore'] ?? meta['currentScore']),
                        impactDimensions: (meta['primaryImpactDimension'] ?? meta['primaryDimension']) ? [(meta['primaryImpactDimension'] ?? meta['primaryDimension']) as string] : undefined
                    };
                }
                break;
            case SecurityEventType.ATTACK_STARTED:
            case SecurityEventType.ATTACK_PROGRESS:
            case SecurityEventType.ATTACK_DETECTED:
            case SecurityEventType.ATTACK_STOPPED:
            case SecurityEventType.ATTACK_FAILED:
            case SecurityEventType.ATTACK_COMPLETED:
                if (meta['attackType'] || meta['intensity'] !== undefined) {
                    return {
                        id, incidentId, timestamp,
                        category: EvidenceCategory.ATTACK,
                        description: `Attack state updated`,
                        attackType: meta['attackType'] as AttackType,
                        attackIntensity: this.safeNum(meta['intensity'])
                    };
                }
                break;
            case SecurityEventType.MITIGATION_RECOMMENDED:
            case SecurityEventType.MITIGATION_APPLIED:
            case SecurityEventType.MITIGATION_STOPPED:
                if (meta['mitigationType']) {
                    let mStatus = MitigationStatus.APPLIED;
                    if (event.type === SecurityEventType.MITIGATION_RECOMMENDED) mStatus = MitigationStatus.RECOMMENDED;
                    if (event.type === SecurityEventType.MITIGATION_STOPPED) mStatus = MitigationStatus.STOPPED;
                    return {
                        id, incidentId, timestamp,
                        category: EvidenceCategory.MITIGATION,
                        description: `Mitigation ${meta['mitigationType']} transitioned`,
                        mitigationType: meta['mitigationType'] as MitigationType,
                        mitigationStatus: mStatus
                    };
                }
                break;
            case SecurityEventType.RECOVERY_STARTED:
            case SecurityEventType.RECOVERY_COMPLETED:
            case SecurityEventType.RECOVERY_FAILED:
                let rStatus = MitigationStatus.VERIFYING;
                if (event.type === SecurityEventType.RECOVERY_COMPLETED) rStatus = MitigationStatus.RECOVERED;
                if (event.type === SecurityEventType.RECOVERY_FAILED) rStatus = MitigationStatus.FAILED;

                return {
                    id, incidentId, timestamp,
                    category: EvidenceCategory.RECOVERY,
                    description: `Recovery phase: ${event.type}`,
                    mitigationType: meta['mitigationType'] as MitigationType | undefined,
                    mitigationStatus: rStatus
                };
        }
        return null;
    }

    private updateIncident(incident: Incident, event: SecurityEvent, timeline: IncidentTimelineEntry, evidence: IncidentEvidence | null): void {
        let newStatus = incident.status;

        // Lifecycle Transitions
        if (event.type === SecurityEventType.ATTACK_STARTED || event.type === SecurityEventType.ATTACK_DETECTED) {
            if (newStatus === IncidentStatus.OPEN) newStatus = IncidentStatus.INVESTIGATING;
        }

        if (event.type === SecurityEventType.MITIGATION_APPLIED) {
            newStatus = IncidentStatus.MITIGATED;
        }

        if (event.type === SecurityEventType.RECOVERY_COMPLETED) {
            // RECOVERY_COMPLETED is the lifecycle source of truth. The event
            // is correlated by attack ID when present and must complete that
            // exact incident even if an earlier mitigation event was delayed.
            newStatus = IncidentStatus.RECOVERED;
        }

        const meta = event.metadata;
        
        let newPeakRiskLevel = incident.peakRiskLevel;
        let newPeakRiskScore = incident.peakRiskScore;
        let newPeakImpactLevel = incident.peakImpactLevel;
        let newPeakImpactScore = incident.peakImpactScore;
        let newAttackId = incident.attackId;
        let newAttackType = incident.attackType;
        let newMitigationType = incident.mitigationType;
        let newMitigationStatus = incident.mitigationStatus;
        let newMitigationId = incident.mitigationId;

        const eventAttackId = this.getEventAttackId(event);
        if (eventAttackId && !newAttackId) newAttackId = eventAttackId;

        // Process Evidence for Peak Tracking
        if (evidence) {
            if (evidence.category === EvidenceCategory.RISK) {
                if (evidence.riskLevel) {
                    newPeakRiskLevel = this.getHighestRisk(incident.peakRiskLevel, evidence.riskLevel);
                }
                if (evidence.riskScore !== undefined) {
                    newPeakRiskScore = Math.max(incident.peakRiskScore || 0, evidence.riskScore);
                }
            }

            if (evidence.category === EvidenceCategory.IMPACT) {
                if (evidence.impactLevel) {
                    newPeakImpactLevel = this.getHighestImpact(incident.peakImpactLevel, evidence.impactLevel);
                }
                if (evidence.impactScore !== undefined) {
                    newPeakImpactScore = Math.max(incident.peakImpactScore || 0, evidence.impactScore);
                }
            }

            if (evidence.category === EvidenceCategory.ATTACK && evidence.attackType) {
                newAttackType = evidence.attackType;
            }

            if (evidence.category === EvidenceCategory.MITIGATION || evidence.category === EvidenceCategory.RECOVERY) {
                if (evidence.mitigationType) newMitigationType = evidence.mitigationType;
                if (evidence.mitigationStatus) newMitigationStatus = evidence.mitigationStatus;
                if (meta['mitigationId']) newMitigationId = meta['mitigationId'] as string;
            }
        }

        const updated: Incident = { 
            ...incident, 
            updatedAt: event.timestamp,
            status: newStatus,
            timelineEntryIds: [...incident.timelineEntryIds, timeline.id],
            evidenceIds: evidence ? [...incident.evidenceIds, evidence.id] : incident.evidenceIds,
            peakRiskLevel: newPeakRiskLevel,
            peakRiskScore: newPeakRiskScore,
            peakImpactLevel: newPeakImpactLevel,
            peakImpactScore: newPeakImpactScore,
            attackId: newAttackId,
            attackType: newAttackType,
            mitigationType: newMitigationType,
            mitigationStatus: newMitigationStatus,
            mitigationId: newMitigationId
        };

        // Replace in array
        this._incidents.update(list => list.map(i => i.id === incident.id ? updated : i));
    }

    private getHighestRisk(current: RiskLevel | undefined, next: RiskLevel): RiskLevel {
        const levels = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL];
        if (!current) return next;
        return levels.indexOf(next) > levels.indexOf(current) ? next : current;
    }

    private getHighestImpact(current: ImpactLevel | undefined, next: ImpactLevel): ImpactLevel {
        const levels = [ImpactLevel.LOW, ImpactLevel.MEDIUM, ImpactLevel.HIGH, ImpactLevel.CRITICAL];
        if (!current) return next;
        return levels.indexOf(next) > levels.indexOf(current) ? next : current;
    }

    /** Resets all in-memory incident, timeline, evidence, and dedup state. */
    public reset(): void {
        this._incidents.set([]);
        this._timelineEntries.set([]);
        this._evidence.set([]);
        this.processedEventKeys.clear();
        this.twinIdByMac.clear();
    }

    private safeNum(val: any): number | undefined {
        if (typeof val === 'number' && !isNaN(val) && isFinite(val)) {
            return val;
        }
        if (typeof val === 'string') {
            const parsed = parseFloat(val);
            if (!isNaN(parsed) && isFinite(parsed)) return parsed;
        }
        return undefined;
    }
}
