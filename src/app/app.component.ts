import {
    AfterViewInit,
    Component,
    HostListener,
    inject,
    Signal,
    viewChild,
} from "@angular/core";
import { Router as NavigationRouter, RouterOutlet } from "@angular/router";
import { CanvasComponent } from "@components/canvas/canvas.component";
import { ConnectionComponent } from "@components/connection/connection.component";
import { MenuBarComponent } from "@components/menu-bar/menu-bar.component";
import { NodeComponent } from "@components/node/node.component";
import { HlmContextMenuImports } from "@components/ui/context-menu/src";
import { HlmDropdownMenuImports } from "@components/ui/dropdown-menu/src";
import { Connection } from "@models/connection";
import { Node, NodeType } from "@models/node";
import { Router } from "@models/router";
import { NgIcon, provideIcons } from "@ng-icons/core";
import {
    lucideChevronsLeftRightEllipsis,
    lucideGhost,
    lucideSettings,
    lucideTrash,
} from "@ng-icons/lucide";
import { TranslateModule } from "@ngx-translate/core";
import { ConfigService } from "@services/config.service";
import { DigitalTwinService } from "@services/digital-twin.service";
import { LibraryService } from "@services/library.service";
import { ModelsService } from "@services/models.service";
import { NetworkService } from "@services/network.service";
import { StateService } from "@services/state.service";
import { HlmButtonImports } from "@spartan-ng/helm/button";
import { HlmToasterImports } from "@spartan-ng/helm/sonner";
import { floatAnimation } from "./app.routes.transition";

@Component({ template: "" })
export class BlankComponent {}

@Component({
    selector: "app-root",
    imports: [
        RouterOutlet,
        CanvasComponent,
        ConnectionComponent,
        HlmButtonImports,
        HlmDropdownMenuImports,
        HlmContextMenuImports,
        HlmToasterImports,
        MenuBarComponent,
        NodeComponent,
        NgIcon,
        TranslateModule,
    ],
    providers: [
        provideIcons({
            lucideChevronsLeftRightEllipsis,
            lucideGhost,
            lucideSettings,
            lucideTrash,
        }),
    ],
    templateUrl: "app.component.html",
    animations: [floatAnimation],
    host: {
        "[class.high-contrast]": "config.highContrast()",
    },
})
export class AppComponent implements AfterViewInit {
    public readonly navigationRouter: NavigationRouter =
        inject(NavigationRouter);
    public readonly config: ConfigService = inject(ConfigService);
    public readonly state: StateService = inject(StateService);
    public readonly network: NetworkService = inject(NetworkService);
    /**
     * Eagerly instantiate the DigitalTwinService at application startup.
     * This guarantees that Digital Twin ↔ MAC mappings and the telemetry/security
     * pipeline exist before the first simulated attack is launched.
     */
    public readonly digitalTwin: DigitalTwinService = inject(DigitalTwinService);
    public readonly library: LibraryService = inject(LibraryService);
    public readonly model: ModelsService = inject(ModelsService);
    public readonly NodeType: typeof NodeType = NodeType;
    protected readonly canvas: Signal<CanvasComponent> =
        viewChild.required(CanvasComponent);
    protected get nodes(): Node[] {
        return this.network.nodes;
    }
    protected get router(): Router | undefined {
        return this.network.router;
    }
    protected get connections(): Connection[] {
        return this.router?.connections ?? [];
    }

    public ngAfterViewInit(): void {
        this.onCenter("instant");
    }

    protected getAnimationData(outlet: RouterOutlet) {
        if (outlet && !outlet.isActivated) return "_";
        return outlet.activatedRoute.snapshot.params["mac"] ?? "_";
    }

    @HostListener("document:keydown.meta.n", ["$event"])
    protected onNewFile(event?: Event) {
        event?.preventDefault();
        this.network.new();
    }

    @HostListener("document:keydown.meta.o", ["$event"])
    protected onOpenFile(event?: Event) {
        event?.preventDefault();
        this.network.loadFromFile();
    }

    protected onLoadExternalLibrary(event?: Event) {
        event?.preventDefault();
        this.library.loadFromFile();
    }

    protected onDeleteExternalLibrary(event?: Event) {
        event?.preventDefault();
        this.library.deleteFile();
    }

    protected onLoadModels(event?: Event) {
        event?.preventDefault();
        this.model.loadFromFile();
    }

    protected onDeleteModels(event?: Event) {
        event?.preventDefault();
        this.model.deleteFile();
    }

    @HostListener("document:keydown.meta.s", ["$event"])
    protected onSaveFile(event?: Event) {
        event?.preventDefault();
        this.network.saveToFile();
    }

    @HostListener("document:keydown.meta.z", ["$event"])
    protected onUndo(event?: Event) {
        event?.preventDefault();
        this.state.undo();
    }

    @HostListener("document:keydown.meta.shift.z", ["$event"])
    protected onRedo(event?: Event) {
        event?.preventDefault();
        this.state.redo();
    }

    @HostListener("document:keydown.meta.shift.r", [
        "NodeType.RouterTypes",
        "$event",
    ])
    @HostListener("document:keydown.meta.shift.d", [
        "NodeType.DeviceTypes",
        "$event",
    ])
    protected onInsertNode(
        type?: NodeType | readonly NodeType[] | NodeType[],
        event?: Event,
    ) {
        const { scrollWidth, scrollHeight, scrollLeft, scrollTop } =
            this.canvas().frame().nativeElement;
        const { left, top, width, height } = this.canvas()
            .frame()
            .nativeElement.getBoundingClientRect();
        const centerX = scrollWidth / 2;
        const centerY = scrollHeight / 2;

        event?.preventDefault();
        if (event instanceof MouseEvent) {
            const { clientX, clientY } = event;

            this.network.addNode(type, {
                x: (clientX - left + scrollLeft - centerX) / this.config.zoom(),
                y: (centerY - (clientY - top + scrollTop)) / this.config.zoom(),
            });
        } else {
            this.network.addNode(type, {
                x:
                    (width / 2 - left + scrollLeft - centerX) /
                    this.config.zoom(),
                y:
                    (centerY - (height / 2 - top + scrollTop)) /
                    this.config.zoom(),
            });
        }
    }

    protected onChangeLanguage(lang: string) {
        this.config.language.set(lang);
    }

    protected onHighContrast() {
        this.config.highContrast.update((prev) => !prev);
    }

    protected onShowGrid() {
        this.config.grid.update((prev) => !prev);
    }

    @HostListener("document:keydown.alt.0", ["'smooth'", "$event"])
    protected onCenter(behavior: ScrollBehavior, event?: Event) {
        const frame = this.canvas().frame().nativeElement;
        const { scrollHeight, clientHeight, scrollWidth, clientWidth } = frame;

        event?.preventDefault();
        frame.scrollTo({
            top: (scrollHeight - clientHeight) / 2,
            left: (scrollWidth - clientWidth) / 2,
            behavior,
        });
    }

    @HostListener("document:keydown.meta.0", ["$event"])
    protected onZoomReset(event?: Event) {
        event?.preventDefault();
        this.config.resetZoom();
    }

    @HostListener("document:keydown.meta.+", ["$event"])
    protected onZoomIn(event?: Event) {
        event?.preventDefault();
        this.config.zoomIn();
    }

    @HostListener("document:keydown.meta.-", ["$event"])
    protected onZoomOut(event?: Event) {
        event?.preventDefault();
        this.config.zoomOut();
    }

    protected onDeleteNode(mac: string, event?: Event) {
        event?.preventDefault();
        this.network.deleteNode(mac);
    }

    protected onNodeTraffic(mac: string, event?: Event) {
        event?.preventDefault();
        this.navigationRouter.navigate([mac, "network-traffic"]);
    }

    protected onNodeAttack(mac: string, event?: Event) {
        event?.preventDefault();
        this.navigationRouter.navigate([mac, "attack"]);
    }

    protected onNodeConfig(mac: string, event?: Event) {
        event?.preventDefault();
        this.navigationRouter.navigate([mac, "configuration"]);
    }
}
