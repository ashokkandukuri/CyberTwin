import { CommonModule } from "@angular/common";
import { Component, computed, inject, input, InputSignal } from "@angular/core";
import { Connection, ConnectionStatus } from "@models/connection";
import { Position } from "@models/position";
import { EditConnectionDialogComponent } from "@routes/dialogs/edit-connection-dialog.component";
import { AttackEngineService } from "@services/attack-engine.service";
import { SecurityEventService } from "@services/security-event.service";
import { HlmDialogService } from "@spartan-ng/helm/dialog";
import { isConnectionUnderActiveAttack } from "@utils/topology-attack-visual";

@Component({
    selector: "app-connection",
    imports: [CommonModule],
    templateUrl: "connection.component.html",
    styleUrl: "connection.component.css",
    host: { class: "contents" },
})
export class ConnectionComponent {
    public readonly dialog: HlmDialogService = inject(HlmDialogService);
    public readonly connection: InputSignal<Connection> = input.required();
    private readonly attackEngine = inject(AttackEngineService);
    private readonly securityEvents = inject(SecurityEventService);
    protected readonly attackActive = computed(() =>
        isConnectionUnderActiveAttack(
            this.connection(),
            this.attackEngine.activeAttacks(),
            this.securityEvents.events(),
        ),
    );

    protected get animate(): boolean {
        return (
            !this.attackActive() &&
            this.connection().status !== ConnectionStatus.IDLE
        );
    }
    protected get reverse(): boolean {
        return this.connection().status === ConnectionStatus.REVERSE;
    }
    protected get node1(): Position {
        return this.connection().node1.position;
    }
    protected get node2(): Position {
        return this.connection().node2.position;
    }
    protected get point(): Position {
        const d = 60;
        const dx = this.node2.x - this.node1.x;
        const dy = this.node2.y - this.node1.y;
        const len = Math.sqrt(dx * dx + dy * dy);

        if (len === 0) return { x: this.node1.x, y: this.node1.y };
        return {
            x: this.node1.x + (dx / len) * Math.min(d, len / 2),
            y: this.node1.y + (dy / len) * Math.min(d, len / 2),
        };
    }
    protected get w(): number {
        return Math.abs(this.node2.x - this.node1.x) + 60;
    }
    protected get h(): number {
        return Math.abs(this.node2.y - this.node1.y) + 60;
    }
    protected get t(): Position {
        return {
            x: (this.node1.x + this.node2.x) / 2 - this.w / 2,
            y: (this.node1.y + this.node2.y) / 2 + this.h / 2,
        };
    }

    protected onClick(): void {
        this.dialog.open(EditConnectionDialogComponent, {
            context: { connection: this.connection() },
        });
    }
}
