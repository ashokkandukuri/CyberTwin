import { CommonModule } from "@angular/common";
import {
    Component,
    ElementRef,
    inject,
    Signal,
    viewChild,
} from "@angular/core";
import { ConfigService } from "@services/config.service";

@Component({
    selector: "app-canvas",
    imports: [CommonModule],
    template: `
        <div
            #frame
            class="frame fixed top-0 left-0 h-screen w-screen cursor-default overflow-scroll">
            <div
                [ngStyle]="{
                    width: config.size() * config.zoom() + 'px',
                    height: config.size() * config.zoom() + 'px',
                }"
                class="m-auto flex items-center justify-center overflow-visible">
                <div
                    [ngStyle]="{
                        minWidth: config.size() + 'px',
                        maxWidth: config.size() + 'px',
                        minHeight: config.size() + 'px',
                        maxHeight: config.size() + 'px',
                        transform: 'scale(' + config.zoom() + ')',
                    }"
                    class="relative overflow-hidden transition-transform"
                    [ngClass]="{ 'grid-view': showGrid() }">
                    <ng-content></ng-content>
                </div>
            </div>
        </div>
    `,
    styles: `
        @reference "../../../styles.css";

        .frame {
            @apply bg-background;

            ::ng-deep .high-contrast & {
                @apply !bg-border;
            }
        }

        .grid-view {
            background-image: radial-gradient(
                circle,
                var(--border) 1.5px,
                transparent 1.5px
            );
            background-size: 20px 20px;

            ::ng-deep .high-contrast & {
                background-image: radial-gradient(
                    circle,
                    var(--muted-foreground) 1.5px,
                    transparent 1.5px
                );
            }
        }
    `,
})
export class CanvasComponent {
    public readonly config: ConfigService = inject(ConfigService);
    public readonly frame: Signal<ElementRef<HTMLDivElement>> =
        viewChild.required("frame");
    protected readonly showGrid: Signal<boolean> = this.config.grid;
}
