import { SecurityEventType } from "./security-event";

/**
 * Represents one chronological event during an incident's lifecycle.
 * Plain, immutable data object safe for serialization.
 */
export interface IncidentTimelineEntry {
    readonly id: string;
    readonly incidentId: string;
    readonly timestamp: Date;
    
    /** The categorized type of event matching the underlying SecurityEvent */
    readonly eventType: SecurityEventType;
    
    /** Short descriptive title for the timeline */
    readonly title: string;
    
    /** Detailed textual summary of what occurred */
    readonly summary: string;
    
    /** Reference to the raw SecurityEvent that triggered this timeline entry (if applicable) */
    readonly sourceSecurityEventId?: string;
    
    /** 
     * Extracted JSON-safe metadata related to this specific point in time. 
     * No services, timers, or object references permitted.
     */
    readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
}
