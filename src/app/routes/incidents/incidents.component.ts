import { CommonModule } from "@angular/common";
import { Component, computed, inject, signal, effect } from "@angular/core";
import { RouterModule } from "@angular/router";
import { TranslateModule } from "@ngx-translate/core";
import { NgIcon, provideIcons } from "@ng-icons/core";
import { 
    lucideShieldAlert, 
    lucideActivity, 
    lucideShieldCheck,
    lucideAlertTriangle,
    lucideClock,
    lucideInfo,
    lucideList,
    lucideGhost,
    lucideShield
} from "@ng-icons/lucide";
import { HlmBadgeImports } from "@spartan-ng/helm/badge";
import { HlmButtonImports } from "@spartan-ng/helm/button";
import { HlmCardImports } from "@spartan-ng/helm/card";
import { HlmSeparatorImports } from "@spartan-ng/helm/separator";
import { IncidentExplanation, IncidentExplanationService } from "@services/incident-explanation.service";
import { IncidentCorrelationService } from "@services/incident-correlation.service";
import { Incident, IncidentStatus } from "@models/incident";
import { IncidentTimelineEntry } from "@models/incident-timeline-entry";
import { IncidentEvidence, EvidenceCategory } from "@models/incident-evidence";
import { RiskLevel } from "@models/risk";
import { ImpactLevel } from "@models/impact";
import {
    getIncidentLifecycleProgress,
    INCIDENT_LIFECYCLE_ORDER,
    IncidentLifecycleStep,
} from "./incident-lifecycle";

const LIFECYCLE_STEP_CONTENT: Readonly<
    Record<IncidentLifecycleStep, { title: string; description: string; icon: string }>
> = {
    investigating: {
        title: "INVESTIGATING",
        description: "Attack detected and being analyzed",
        icon: "activity",
    },
    mitigated: {
        title: "MITIGATED",
        description: "Attack controlled by simulated mitigation",
        icon: "shield",
    },
    recovered: {
        title: "RECOVERED",
        description: "System health restored and verified",
        icon: "shield-check",
    },
};

@Component({
    selector: "app-incidents",
    imports: [
        CommonModule,
        RouterModule,
        TranslateModule,
        NgIcon,
        HlmBadgeImports,
        HlmButtonImports,
        HlmCardImports,
        HlmSeparatorImports
    ],
    providers: [
        provideIcons({
            lucideShieldAlert,
            lucideActivity,
            lucideShieldCheck,
            lucideAlertTriangle,
            lucideClock,
            lucideInfo,
            lucideList,
            lucideGhost,
            lucideShield
        })
    ],
    templateUrl: "./incidents.component.html",
    host: {
        class: "fixed inset-0 top-16 z-50 flex flex-col bg-background p-6 overflow-hidden"
    }
})
export class IncidentsComponent {
    private readonly correlation = inject(IncidentCorrelationService);
    private readonly explanation = inject(IncidentExplanationService);

    protected readonly IncidentStatus = IncidentStatus;
    protected readonly RiskLevel = RiskLevel;
    protected readonly ImpactLevel = ImpactLevel;
    protected readonly EvidenceCategory = EvidenceCategory;

    // Filters
    protected filterStatus = signal<IncidentStatus | 'ALL' | 'CRITICAL_HIGH' | 'ACTIVE'>('ALL');

    // All incidents from correlation
    protected incidents = this.correlation.incidents;

    // Filtered incidents
    protected filteredIncidents = computed(() => {
        // The Security Incidents view is specifically the history of simulated
        // attacks. Supporting signals remain available inside each incident's
        // evidence and timeline.
        const all = this.incidents().filter((incident) => Boolean(incident.attackId));
        const f = this.filterStatus();
        let filtered = all;

        if (f === 'ACTIVE') {
            filtered = all.filter(i => i.status === IncidentStatus.OPEN || i.status === IncidentStatus.INVESTIGATING);
        } else if (f === IncidentStatus.RECOVERED) {
            filtered = all.filter(i => i.status === IncidentStatus.RECOVERED);
        } else if (f === 'CRITICAL_HIGH') {
            filtered = all.filter(i => 
                i.peakRiskLevel === RiskLevel.CRITICAL || 
                i.peakRiskLevel === RiskLevel.HIGH ||
                i.peakImpactLevel === ImpactLevel.CRITICAL ||
                i.peakImpactLevel === ImpactLevel.HIGH
            );
        }

        return filtered.sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime());
    });

    // Selection
    protected selectedIncidentId = signal<string | null>(null);

    protected selectedIncident = computed(() => {
        const id = this.selectedIncidentId();
        if (!id) return null;
        return this.incidents().find(i => i.id === id && Boolean(i.attackId)) || null;
    });

    protected readonly lifecycleSteps = INCIDENT_LIFECYCLE_ORDER.map((id) => ({
        id,
        ...LIFECYCLE_STEP_CONTENT[id],
    }));

    protected lifecycleProgress = computed(() => {
        const incident = this.selectedIncident();
        return incident ? getIncidentLifecycleProgress(incident.status) : null;
    });

    protected lifecycleState(step: IncidentLifecycleStep) {
        return this.lifecycleProgress()?.[step] ?? "pending";
    }

    protected isLifecycleConnectorComplete(nextStepIndex: number): boolean {
        const progress = this.lifecycleProgress();
        if (!progress) return false;
        return nextStepIndex === 1
            ? progress.investigating === "completed"
            : progress.mitigated === "completed";
    }

    protected selectedTimeline = computed(() => {
        const id = this.selectedIncidentId();
        if (!id) return [];
        return this.correlation.timelineEntries()
            .filter(e => e.incidentId === id)
            .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    });

    protected selectedEvidence = computed(() => {
        const id = this.selectedIncidentId();
        if (!id) return [];
        return this.correlation.evidence().filter(e => e.incidentId === id);
    });

    // Explanation generation logic (reactive but deferred to effect or computed)
    protected currentExplanation = signal<IncidentExplanation | null>(null);

    constructor() {
        effect(() => {
            const incident = this.selectedIncident();
            const timeline = this.selectedTimeline();
            const evidence = this.selectedEvidence();
            
            if (incident) {
                // Determine deterministically based on input data
                const exp = this.explanation.explain(incident, timeline, evidence);
                this.currentExplanation.set(exp);
            } else {
                this.currentExplanation.set(null);
            }
        }, { allowSignalWrites: true });
    }

    protected selectIncident(id: string) {
        this.selectedIncidentId.set(id);
    }

    protected setFilter(filter: IncidentStatus | 'ALL' | 'CRITICAL_HIGH' | 'ACTIVE') {
        this.filterStatus.set(filter);
    }

    protected getStatusVariant(status: IncidentStatus): "default" | "destructive" | "outline" | "secondary" {
        switch (status) {
            case IncidentStatus.OPEN:
            case IncidentStatus.INVESTIGATING: return "destructive";
            case IncidentStatus.MITIGATED: return "secondary";
            case IncidentStatus.RECOVERED: return "outline";
            case IncidentStatus.CLOSED: return "default";
            default: return "default";
        }
    }

    protected getLevelVariant(level: string | undefined): "default" | "destructive" | "outline" | "secondary" {
        if (!level) return "outline";
        switch (level) {
            case 'CRITICAL':
            case 'HIGH': return "destructive";
            case 'MEDIUM': return "secondary";
            case 'LOW': return "outline";
            default: return "default";
        }
    }
}
