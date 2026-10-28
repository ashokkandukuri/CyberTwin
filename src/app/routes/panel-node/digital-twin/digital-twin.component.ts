import { CommonModule } from "@angular/common";
import { Component, computed, inject, input, InputSignal, Signal } from "@angular/core";
import { Node } from "@models/node";
import { DigitalTwin } from "@models/digital-twin";
import { stateToLabel, stateSeverityLevel } from "@models/device-state";
import { TwinTelemetry } from "@models/telemetry";
import { TranslateModule } from "@ngx-translate/core";
import { NgIcon, provideIcons } from "@ng-icons/core";
import {
    lucideShield,
    lucideActivity,
    lucideCpu,
    lucideHardDrive,
    lucideThermometer,
    lucideBatteryFull,
    lucideWifi,
    lucideGauge,
} from "@ng-icons/lucide";
import { DigitalTwinService } from "@services/digital-twin.service";
import { BadgeVariants, HlmBadgeImports } from "@spartan-ng/helm/badge";

@Component({
    imports: [
        CommonModule,
        TranslateModule,
        NgIcon,
        HlmBadgeImports,
    ],
    providers: [
        provideIcons({
            lucideShield,
            lucideActivity,
            lucideCpu,
            lucideHardDrive,
            lucideThermometer,
            lucideBatteryFull,
            lucideWifi,
            lucideGauge,
        }),
    ],
    templateUrl: "digital-twin.component.html",
    host: { class: "flex flex-col gap-3 pb-6" },
})
export class DigitalTwinComponent {
    protected readonly node: InputSignal<Node> = input.required<Node>();
    private readonly twinService: DigitalTwinService = inject(DigitalTwinService);

    /** Reactive twin lookup — recalculates when service revision changes */
    protected readonly twin: Signal<DigitalTwin | undefined> = computed(() => {
        // Touch the twins signal to get reactivity on twin updates
        this.twinService.twins();
        return this.twinService.getTwin(this.node().mac);
    });

    protected readonly telemetry: Signal<TwinTelemetry | undefined> = computed(() => {
        return this.twin()?.telemetry;
    });

    protected readonly stateLabel: Signal<string> = computed(() => {
        const twin = this.twin();
        return twin ? stateToLabel(twin.state) : "STATE_OFFLINE";
    });

    protected readonly stateSeverity: Signal<number> = computed(() => {
        const twin = this.twin();
        return twin ? stateSeverityLevel(twin.state) : 1;
    });

    protected readonly stateBadgeVariant: Signal<BadgeVariants["variant"]> = computed(() => {
        switch (this.stateSeverity()) {
            case 0: return "default";
            case 1: return "secondary";
            case 2: return "outline";
            case 3: return "destructive";
            default: return "secondary";
        }
    });
}
