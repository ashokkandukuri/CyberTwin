import { CommonModule } from "@angular/common";
import { Component, computed, inject, Signal } from "@angular/core";
import { Node } from "@models/node";
import { TranslateModule } from "@ngx-translate/core";
import { BrnDialogRef, injectBrnDialogContext } from "@spartan-ng/brain/dialog";
import { BrnSelectImports } from "@spartan-ng/brain/select";
import { HlmButtonImports } from "@spartan-ng/helm/button";
import { HlmDialogImports } from "@spartan-ng/helm/dialog";
import { HlmSelectImports } from "@spartan-ng/helm/select";

export interface DeleteNodeDialogContext {
    node: Node;
}

@Component({
    selector: "app-delete-node-dialog",
    imports: [
        CommonModule,
        TranslateModule,
        BrnSelectImports,
        HlmButtonImports,
        HlmDialogImports,
        HlmSelectImports,
    ],
    template: `
        <hlm-dialog-header>
            <h3 hlmDialogTitle>
                {{ "DELETE_NODE" | translate: { name: name() } }}
            </h3>
        </hlm-dialog-header>
        <p hlmDialogDescription>
            {{ "DELETE_DESC" | translate }}
        </p>
        <hlm-dialog-footer>
            <button hlmBtn variant="outline" (click)="cancel()">
                {{ "CANCEL" | translate }}
            </button>
            <button hlmBtn variant="destructive" (click)="delete()">
                {{ "DELETE" | translate }}
            </button>
        </hlm-dialog-footer>
    `,
    host: { class: "min-w-96 flex flex-col gap-4" },
})
export class DeleteNodeDialogComponent {
    protected readonly ref: BrnDialogRef<DeleteNodeDialogContext> = inject(
        BrnDialogRef<DeleteNodeDialogContext>,
    );
    protected readonly context =
        injectBrnDialogContext<DeleteNodeDialogContext>();
    protected readonly name: Signal<string> = computed(
        () => this.context.node.name,
    );

    protected cancel() {
        this.ref.close();
    }

    protected delete() {
        this.ref.close({ node: this.context.node });
    }
}
