import { CommonModule } from "@angular/common";
import {
    AfterViewInit,
    ChangeDetectorRef,
    Component,
    input,
    InputSignal,
} from "@angular/core";
import { RouterModule, RouterOutlet } from "@angular/router";
import { Node, NodeType } from "@models/node";
import { NgIcon, provideIcons } from "@ng-icons/core";
import { lucideGhost, lucideShield, lucideX } from "@ng-icons/lucide";
import { TranslateModule } from "@ngx-translate/core";
import { HlmButtonImports } from "@spartan-ng/helm/button";
import { HlmCard, HlmCardImports } from "@spartan-ng/helm/card";
import { fadeAnimation } from "../../app.routes.transition";

@Component({
    selector: "app-panel-node",
    imports: [
        CommonModule,
        RouterModule,
        TranslateModule,
        HlmButtonImports,
        HlmCardImports,
        NgIcon,
    ],
    providers: [provideIcons({ lucideGhost, lucideShield, lucideX })],
    templateUrl: "panel-node.component.html",
    host: {
        class: "fixed right-5 top-1/2 flex flex-col max-h-[calc(100%-2.5rem)] min-w-[512px] max-w-[calc(75%-2.5rem)] -translate-y-1/2 rounded-xl overflow-hidden gap-0! pt-6 pb-0",
    },
    hostDirectives: [HlmCard],
    animations: [fadeAnimation],
})
export class PanelNodeComponent implements AfterViewInit {
    protected readonly node: InputSignal<Node> = input.required<Node>();
    protected readonly NodeType: typeof NodeType = NodeType;
    private _loaded: boolean = false;

    constructor(private readonly cdr: ChangeDetectorRef) {}

    public ngAfterViewInit(): void {
        this._loaded = true;
        this.cdr.detectChanges();
    }

    protected getAnimationData(outlet: RouterOutlet) {
        if ((outlet && !outlet.isActivated) || !this._loaded) return "_";
        return outlet.activatedRoute.snapshot.url[0]?.path ?? "_";
    }
}
