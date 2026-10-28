import { IncidentStatus } from "@models/incident";

export type IncidentLifecycleStep = "investigating" | "mitigated" | "recovered";
export type IncidentLifecycleStepState = "pending" | "active" | "completed";

export const INCIDENT_LIFECYCLE_ORDER: readonly IncidentLifecycleStep[] = [
    "investigating",
    "mitigated",
    "recovered",
];

export type IncidentLifecycleProgress = Readonly<
    Record<IncidentLifecycleStep, IncidentLifecycleStepState>
>;

/** Maps the existing incident status to the three presentation-only stages. */
export function getIncidentLifecycleProgress(
    status: IncidentStatus,
): IncidentLifecycleProgress {
    switch (status) {
        case IncidentStatus.MITIGATED:
            return {
                investigating: "completed",
                mitigated: "active",
                recovered: "pending",
            };
        case IncidentStatus.RECOVERED:
            return {
                investigating: "completed",
                mitigated: "completed",
                recovered: "completed",
            };
        case IncidentStatus.OPEN:
        case IncidentStatus.INVESTIGATING:
        case IncidentStatus.CLOSED:
        default:
            return {
                investigating: "active",
                mitigated: "pending",
                recovered: "pending",
            };
    }
}
