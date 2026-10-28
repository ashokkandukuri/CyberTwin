import { CommonModule } from "@angular/common";
import {
    Component,
    computed,
    inject,
    model,
    ModelSignal,
    Signal,
} from "@angular/core";
import { FormsModule } from "@angular/forms";
import { NodeType } from "@models/node";
import { TranslateModule } from "@ngx-translate/core";
import { BrnDialogRef, injectBrnDialogContext } from "@spartan-ng/brain/dialog";
import { BrnSelectImports } from "@spartan-ng/brain/select";
import { HlmButtonImports } from "@spartan-ng/helm/button";
import { HlmDialogImports } from "@spartan-ng/helm/dialog";
import { HlmInputImports } from "@spartan-ng/helm/input";
import { HlmLabelImports } from "@spartan-ng/helm/label";
import { HlmSelectImports } from "@spartan-ng/helm/select";

export interface AddNodeDialogContext {
    name: string;
    type: NodeType;
}

@Component({
    selector: "app-add-node-dialog",
    imports: [
        CommonModule,
        FormsModule,
        TranslateModule,
        BrnSelectImports,
        HlmButtonImports,
        HlmDialogImports,
        HlmInputImports,
        HlmLabelImports,
        HlmSelectImports,
    ],
    template: `
        <hlm-dialog-header>
            <h3 hlmDialogTitle>{{ "ADD_NODE" | translate }}</h3>
        </hlm-dialog-header>
        <div class="grid gap-4">
            <div class="grid grid-cols-4 items-center gap-4">
                <label hlmLabel class="justify-end">{{
                    "NAME" | translate
                }}</label>
                <input hlmInput [(ngModel)]="name" class="col-span-3" />
            </div>
            <div class="grid grid-cols-4 items-center gap-4">
                <label hlmLabel class="justify-end">{{
                    "TYPE" | translate
                }}</label>
                <brn-select
                    [(ngModel)]="type"
                    [placeholder]="'SELECT_DEVICE_TYPE' | translate"
                    [disabled]="types().length === 1"
                    class="col-span-3 inline-block">
                    <hlm-select-trigger class="w-full">
                        <hlm-select-value class="block" />
                    </hlm-select-trigger>
                    <hlm-select-content>
                        @for (item of types(); track $index) {
                            <hlm-option [value]="item">{{
                                NodeType.toString(item) | translate
                            }}</hlm-option>
                        }
                    </hlm-select-content>
                </brn-select>
            </div>
        </div>
        <hlm-dialog-footer>
            <button hlmBtn [disabled]="!(name() && type())" (click)="submit()">
                {{ "ADD" | translate }}
            </button>
        </hlm-dialog-footer>
    `,
    host: { class: "min-w-96 flex flex-col gap-4" },
})
export class AddNodeDialogComponent {
    public readonly NodeType: typeof NodeType = NodeType;
    protected readonly ref: BrnDialogRef<AddNodeDialogContext> = inject(
        BrnDialogRef<AddNodeDialogContext>,
    );
    protected readonly context = injectBrnDialogContext<AddNodeDialogContext>();
    protected readonly types: Signal<NodeType[]> = computed(() =>
        Array.isArray(this.context.type)
            ? this.context.type
            : [this.context.type],
    );
    protected readonly name: ModelSignal<string | null> = model<string | null>(
        null,
    );
    protected readonly type: ModelSignal<NodeType | null> =
        model<NodeType | null>(
            this.types().length === 1 ? this.types()[0] : null,
        );

    protected submit() {
        this.ref.close({
            name: this.name()!,
            type: this.type()!,
        });
    }
}
