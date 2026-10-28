import { Injectable, signal, computed, Signal, WritableSignal } from "@angular/core";
import {
    SecurityEvent,
    SecurityEventSeverity,
    CreateSecurityEventParams,
    createSecurityEvent,
} from "@models/security-event";
import { IncidentCorrelationService } from "@services/incident-correlation.service";

/** Maximum number of events to retain in history */
const MAX_EVENT_HISTORY = 500;

/** Severity levels that are considered "active alerts" until explicitly cleared */
const ALERT_SEVERITIES: ReadonlySet<SecurityEventSeverity> = new Set([
    SecurityEventSeverity.HIGH,
    SecurityEventSeverity.CRITICAL,
]);

/**
 * Centralized service for managing security events in the CyberTwin system.
 *
 * Responsibilities:
 * - Emit security events
 * - Retain immutable event history (capped at MAX_EVENT_HISTORY)
 * - Expose recent events and active alerts reactively via Angular signals
 * - Clear alerts only through explicit actions
 *
 * This service is independent of UI components.
 */
@Injectable({ providedIn: "root" })
export class SecurityEventService {
    /** Internal writable signal for the full event history */
    private readonly _events: WritableSignal<readonly SecurityEvent[]> = signal([]);

    /** Internal writable signal for active (uncleared) alert IDs */
    private readonly _activeAlertIds: WritableSignal<ReadonlySet<string>> = signal(new Set());

    /** All events in history (most recent first) */
    public readonly events: Signal<readonly SecurityEvent[]> = this._events.asReadonly();

    /** Number of events in history */
    public readonly eventCount: Signal<number> = computed(() => this._events().length);

    /** Active alerts (high/critical events not yet cleared) */
    public readonly activeAlerts: Signal<readonly SecurityEvent[]> = computed(() => {
        const alertIds = this._activeAlertIds();
        return this._events().filter(e => alertIds.has(e.id));
    });

    constructor(private readonly incidentCorrelation: IncidentCorrelationService) {}

    /** Number of active alerts */
    public readonly activeAlertCount: Signal<number> = computed(() => this.activeAlerts().length);

    /** Most recent events (last 20) */
    public readonly recentEvents: Signal<readonly SecurityEvent[]> = computed(() =>
        this._events().slice(0, 20),
    );

    /**
     * Emits a new security event, adds it to history, and tracks it as an
     * active alert if its severity warrants it.
     *
     * @param params Event creation parameters
     * @returns The created SecurityEvent
     */
    public emit(params: CreateSecurityEventParams): SecurityEvent {
        const event = createSecurityEvent(params);

        // Prepend to history (most recent first), cap size
        this._events.update(events => {
            const updated = [event, ...events];
            if (updated.length > MAX_EVENT_HISTORY) {
                return updated.slice(0, MAX_EVENT_HISTORY);
            }
            return updated;
        });

        // Track as active alert if severity is high or critical
        if (ALERT_SEVERITIES.has(event.severity)) {
            this._activeAlertIds.update(ids => {
                const next = new Set(ids);
                next.add(event.id);
                return next;
            });
        }

        // Send to correlation engine
        this.incidentCorrelation.processEvent(event);

        return event;
    }

    /**
     * Clears a specific alert by ID (removes from active alerts, NOT from history).
     *
     * @param eventId The event ID to clear
     * @returns true if the alert was found and cleared
     */
    public clearAlert(eventId: string): boolean {
        let found = false;
        this._activeAlertIds.update(ids => {
            if (!ids.has(eventId)) return ids;
            found = true;
            const next = new Set(ids);
            next.delete(eventId);
            return next;
        });
        return found;
    }

    /**
     * Clears all active alerts.
     */
    public clearAllAlerts(): void {
        this._activeAlertIds.set(new Set());
    }

    /**
     * Returns events filtered by source MAC address.
     *
     * @param mac The source MAC address
     * @returns Filtered events (most recent first)
     */
    public getEventsBySource(mac: string): SecurityEvent[] {
        return this._events().filter(e => e.source === mac);
    }

    /**
     * Resets the event service (clears all history and alerts).
     * Used when creating a new network.
     */
    public reset(): void {
        this._events.set([]);
        this._activeAlertIds.set(new Set());
        this.incidentCorrelation.reset();
    }
}
