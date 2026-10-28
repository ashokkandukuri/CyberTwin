import { CommonModule } from "@angular/common";
import {
    Component,
    computed,
    effect,
    inject,
    input,
    InputSignal,
    model,
    ModelSignal,
    OnChanges,
    Signal,
    SimpleChanges,
} from "@angular/core";
import { FormsModule } from "@angular/forms";
import { HlmDropdownMenuSeparator } from "@components/ui/dropdown-menu/src";
import { Device } from "@models/device";
import { Node } from "@models/node";
import { Attack, PhantomAttacker } from "@models/phantom-attacker";
import { AttackType, AttackConfig, AttackParameters } from "@models/attack-types";
import { NgIcon, provideIcons } from "@ng-icons/core";
import { lucideUnplug } from "@ng-icons/lucide";
import { TranslateModule } from "@ngx-translate/core";
import { NetworkService } from "@services/network.service";
import { AttackEngineService } from "@services/attack-engine.service";
import { BrnSelectImports } from "@spartan-ng/brain/select";
import { HlmButtonImports } from "@spartan-ng/helm/button";
import { HlmLabelImports } from "@spartan-ng/helm/label";
import { HlmSelectImports } from "@spartan-ng/helm/select";
import { toast } from "ngx-sonner";

/** Attack IDs that are handled by AttackEngineService */
const ENGINE_ATTACK_IDS: ReadonlySet<string> = new Set([
    AttackType.DOS,
    AttackType.MQTT_FLOOD,
    AttackType.SENSOR_SPOOF,
    AttackType.BRUTE_FORCE,
    AttackType.PORT_SCAN,
]);

@Component({
    imports: [
        CommonModule,
        FormsModule,
        TranslateModule,
        BrnSelectImports,
        HlmButtonImports,
        HlmLabelImports,
        HlmDropdownMenuSeparator,
        HlmSelectImports,
        NgIcon,
    ],
    providers: [provideIcons({ lucideUnplug })],
    templateUrl: "attack.component.html",
    host: { class: "flex flex-col gap-4 pb-6" },
})
export class AttackComponent implements OnChanges {
    public readonly network: NetworkService = inject(NetworkService);
    private readonly attackEngine: AttackEngineService = inject(AttackEngineService);
    protected readonly node: InputSignal<Node> = input.required<Node>();
    protected readonly attack: ModelSignal<Attack | null> =
        model<Attack | null>(null);
    protected readonly target: ModelSignal<string | string[] | null> = model<
        string | string[] | null
    >(null);
    protected readonly multipleTargets: Signal<boolean> = computed(
        () => this.attack()?.multiple ?? false,
    );
    protected get canConnect(): boolean {
        return this.network.router !== undefined;
    }
    protected get attacks(): any[] {
        const internalAttacks = (this.node().generator as PhantomAttacker)
            .internalAttacks;
        const externalAttacks = (this.node().generator as PhantomAttacker)
            .externalAttacks;

        if (internalAttacks.length > 0 && externalAttacks.length > 0)
            return [...internalAttacks, "---", ...externalAttacks];
        return [...internalAttacks, ...externalAttacks];
    }
    protected get connectedNodes(): Node[] {
        return this.network.getConnectedNodes(this.node().mac);
    }

    public constructor() {
        effect(() => {
            if (this.multipleTargets())
                this.target.update((value) => {
                    if (value && !Array.isArray(value))
                        return [value as string];
                    return value;
                });
            else
                this.target.update((value) => {
                    if (value && Array.isArray(value)) return value[0];
                    return value;
                });
        });

    }

    protected rememberAttackSelection(value: Attack | null): void {
        if (!value) return;
        const target = this.target();
        const targetIp = Array.isArray(target) ? target[0] : target ?? undefined;
        this.attackEngine.rememberAttackSelection(this.node().mac, value.id, targetIp);
    }

    protected rememberTargetSelection(value: string | string[] | null): void {
        const selectedAttack = this.attack();
        if (!selectedAttack) return;
        const targetIp = Array.isArray(value) ? value[0] : value ?? undefined;
        this.attackEngine.rememberAttackSelection(this.node().mac, selectedAttack.id, targetIp);
    }

    public ngOnChanges(changes: SimpleChanges): void {
        if (!changes["node"]) return;

        const remembered = this.attackEngine.getLastAttackSelection(this.node().mac);
        if (!remembered) {
            this.attack.set(null);
            this.target.set(null);
            return;
        }

        const rememberedAttack = this.attacks.find(
            item => item !== "---" && item.id === remembered.attackId,
        ) as Attack | undefined;

        this.attack.set(rememberedAttack ?? null);
        this.target.set(remembered.targetIp ?? null);
    }

    protected connect() {
        (this.node() as Device).connect(this.network.router!);
    }

    /**
     * Resolves an IP address to a MAC address by looking up connected nodes.
     */
    private _resolveIpToMac(ip: string): string | undefined {
        const node = this.connectedNodes.find(n => n.ip === ip);
        return node?.mac;
    }

    /**
     * Builds default AttackParameters for a given AttackType.
     */
    private _buildDefaultParameters(type: AttackType): AttackParameters {
        switch (type) {
            case AttackType.DOS:
                return { dstPort: 53, ttlRange: [32, 128] as [number, number] };
            case AttackType.MQTT_FLOOD:
                return { topic: "iot/sensors/data", payloadSizeBytes: 1024 };
            case AttackType.SENSOR_SPOOF:
                return { targetField: "temperature", spoofValue: 999 };
            case AttackType.BRUTE_FORCE:
                return { targetService: "SSH" };
            case AttackType.PORT_SCAN:
                return { portRange: [1, 100] as [number, number] };
        }
    }

    protected execute() {
        const attackId = this.attack()!.id;

        // Route Phase 2 attack types through AttackEngineService
        if (ENGINE_ATTACK_IDS.has(attackId)) {
            const targetIp = this.target() as string;
            const targetMac = this._resolveIpToMac(targetIp);

            if (!targetMac) {
                toast.error("Target node not found for IP: " + targetIp);
                return;
            }

            const config: AttackConfig = {
                type: attackId as AttackType,
                sourceNodeMac: this.node().mac,
                targetNodeMac: targetMac,
                durationMs: 30000,
                intensity: 5,
                parameters: this._buildDefaultParameters(attackId as AttackType),
            };

            const result = this.attackEngine.launchAttack(config);
            if (result.valid) {
                toast.success(`Attack ${attackId} launched successfully`);
            } else {
                toast.error(result.error ?? "Attack launch failed");
            }
            return;
        }

        // Legacy external library attacks
        (this.node().generator as PhantomAttacker).attack(
            attackId,
            ...(Array.isArray(this.target()!)
                ? this.target()!
                : [this.target()!]),
        );
    }
}
