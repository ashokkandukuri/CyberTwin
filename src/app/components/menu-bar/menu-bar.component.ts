import { CommonModule } from "@angular/common";
import {
    Component,
    inject,
    input,
    InputSignal,
    output,
    OutputEmitterRef,
} from "@angular/core";
import { HlmDropdownMenuImports } from "@components/ui/dropdown-menu/src";
import { HlmKbdImports } from "@components/ui/kbd/src";
import { HlmMenubarImports } from "@components/ui/menubar/src";
import { RouterModule } from "@angular/router";
import { TranslateModule } from "@ngx-translate/core";
import { ConfigService } from "@services/config.service";
import { NetworkService } from "@services/network.service";
import { StateService } from "@services/state.service";
import { name, version } from "../../../../package.json";

@Component({
    selector: "app-menu-bar",
    imports: [
        CommonModule,
        TranslateModule,
        RouterModule,
        HlmMenubarImports,
        HlmDropdownMenuImports,
        HlmKbdImports,
    ],
    templateUrl: "menu-bar.component.html",
    styles: `
        hlm-dropdown-menu-group > button,
        hlm-dropdown-menu-sub > button {
            text-align: left;
        }
    `,
})
export class MenuBarComponent {
    public readonly config: ConfigService = inject(ConfigService);
    public readonly state: StateService = inject(StateService);
    public readonly network: NetworkService = inject(NetworkService);
    protected readonly onNewFile: OutputEmitterRef<void> = output();
    protected readonly onOpenFile: OutputEmitterRef<void> = output();
    public readonly externalLibrary: InputSignal<boolean> = input.required();
    protected readonly onLoadExternalLibrary: OutputEmitterRef<void> = output();
    protected readonly onDeleteExternalLibrary: OutputEmitterRef<void> =
        output();
    public readonly models: InputSignal<boolean> = input.required();
    protected readonly onLoadModels: OutputEmitterRef<void> = output();
    protected readonly onDeleteModels: OutputEmitterRef<void> = output();
    protected readonly onSaveFile: OutputEmitterRef<void> = output();
    protected readonly onUndo: OutputEmitterRef<void> = output();
    protected get canUndo(): boolean {
        return this.state.canUndo;
    }
    protected readonly onRedo: OutputEmitterRef<void> = output();
    protected get canRedo(): boolean {
        return this.state.canRedo;
    }
    protected readonly onInsertRouter: OutputEmitterRef<void> = output();
    protected readonly onInsertDevice: OutputEmitterRef<void> = output();
    protected get canInsertRouter(): boolean {
        return !this.network.router;
    }
    public readonly language: InputSignal<string> = input.required();
    protected readonly onChangeLanguage: OutputEmitterRef<string> = output();
    public readonly highContrast: InputSignal<boolean> = input.required();
    protected onHighContrast: OutputEmitterRef<void> = output();
    public readonly showGrid: InputSignal<boolean> = input.required();
    protected readonly onShowGrid: OutputEmitterRef<void> = output();
    protected readonly onCenter: OutputEmitterRef<void> = output();
    protected readonly onZoomReset: OutputEmitterRef<void> = output();
    protected readonly onZoomIn: OutputEmitterRef<void> = output();
    protected get canZoomIn(): boolean {
        return this.config.zoom() < 2;
    }
    protected readonly onZoomOut: OutputEmitterRef<void> = output();
    protected get canZoomOut(): boolean {
        return this.config.zoom() > 0.5;
    }
    protected readonly versionName: string = `${name} v${version}`;

    protected handleOnNewFile() {
        this.onNewFile.emit();
    }

    protected handleOnOpenFile() {
        this.onOpenFile.emit();
    }

    protected handleOnLoadExternalLibrary() {
        this.onLoadExternalLibrary.emit();
    }

    protected handleOnDeleteExternalLibrary() {
        this.onDeleteExternalLibrary.emit();
    }

    protected handleOnLoadModels() {
        this.onLoadModels.emit();
    }

    protected handleOnDeleteModels() {
        this.onDeleteModels.emit();
    }

    protected handleOnSaveFile() {
        this.onSaveFile.emit();
    }

    protected handleOnUndo() {
        this.onUndo.emit();
    }

    protected handleOnRedo() {
        this.onRedo.emit();
    }

    protected handleOnInsertRouter() {
        this.onInsertRouter.emit();
    }

    protected handleOnInsertDevice() {
        this.onInsertDevice.emit();
    }

    protected handleOnLanguage(language: string) {
        this.onChangeLanguage.emit(language);
    }

    protected handleOnHighContrast() {
        this.onHighContrast.emit();
    }

    protected handleOnGrid() {
        this.onShowGrid.emit();
    }

    protected handleOnCenter() {
        this.onCenter.emit();
    }

    protected handleOnZoomReset() {
        this.onZoomReset.emit();
    }

    protected handleOnZoomIn() {
        this.onZoomIn.emit();
    }

    protected handleOnZoomOut() {
        this.onZoomOut.emit();
    }

    protected handleOnSourceCode() {
        window.open(
            "https://github.com/gicap-ubu/iot-sim",
            "_blank",
            "noopener noreferrer",
        );
    }

    protected handleOnDocumentation() {
        window.open(
            "https://github.com/gicap-ubu/iot-sim/wiki",
            "_blank",
            "noopener noreferrer",
        );
    }

    protected handleOnLayoutExamples() {
        window.open("/iot-sim/resources/topologies", "_blank", "noopener noreferrer");
    }

    protected handleOnLibraryExamples() {
        window.open("/iot-sim/resources/libs", "_blank", "noopener noreferrer");
    }

    protected handleOnModelsExamples() {
        window.open("/iot-sim/resources/models", "_blank", "noopener noreferrer");
    }
}
