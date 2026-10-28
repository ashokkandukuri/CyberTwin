import {
    computed,
    effect,
    Injectable,
    Signal,
    signal,
    WritableSignal,
} from "@angular/core";
import { TranslateService } from "@ngx-translate/core";

/** Tamaño del canvas. */
export const CANVAS_SIZE: number = 4000;

/**
 * Clase que permite gestionar la configuración de la aplicación.
 */
@Injectable({ providedIn: "root" })
export class ConfigService {
    /** Idioma de la aplicación. */
    public readonly language: WritableSignal<string>;
    public readonly languageList: string[] = [
        "en",
        "es",
        "fr",
        "pt",
        "it",
        "de",
    ];
    /** Visualización de la cuadrícula. */
    public readonly grid: WritableSignal<boolean>;
    /** Modo de alto contraste. */
    public readonly highContrast: WritableSignal<boolean> = signal(false);
    /** El tamaño del canvas. */
    public readonly size: Signal<number> = computed(() => CANVAS_SIZE);
    /** Ampliación de la cuadrícula. */
    public readonly _zoom: WritableSignal<number> = signal(1);
    /** Ampliación de la cuadrícula. */
    public readonly zoom: Signal<number> = this._zoom.asReadonly();

    public constructor(public readonly translate: TranslateService) {
        // Lenguaje
        this.translate.addLangs(this.languageList);
        this.translate.setDefaultLang("en");
        this.language = signal(
            localStorage.getItem("language") ??
                this.translate.getBrowserLang() ??
                "en",
        );
        effect(() => {
            this.translate.use(this.language());
            localStorage.setItem("language", this.language());
        });
        // Visibilidad de la cuadrícula
        this.grid = signal(
            localStorage.getItem("grid") === "false" ? false : true,
        );
        effect(() => localStorage.setItem("grid", this.grid().toString()));
        // Modo de alto contraste
        this.highContrast.set(
            localStorage.getItem("highContrast") === "true" ? true : false,
        );
        effect(() =>
            localStorage.setItem(
                "highContrast",
                this.highContrast().toString(),
            ),
        );
        // Ampliación de la cuadrícula
        this._zoom.set(parseFloat(localStorage.getItem("zoom") ?? "1") ?? 1);
        effect(() => localStorage.setItem("zoom", this._zoom().toString()));
    }

    /**
     * Abre un archivo existente.
     *
     * @param extensions Extensiones de archivo a abrir.
     * @returns Archivo abierto.
     */
    public static async openFile(
        extensions?: string,
        multiple?: boolean,
    ): Promise<any> {
        const input: HTMLInputElement = document.createElement("input");

        input.type = "file";
        input.value = "";
        if (extensions) input.accept = extensions;
        if (multiple) input.multiple = multiple;
        return new Promise<any>((resolve, reject) => {
            input.onchange = async (event: Event) => {
                const files = (event.target as HTMLInputElement).files;

                // Esperamos un segundo para que se pueda cargar el archivo
                await new Promise((_) => setTimeout(_, 1000));
                if (files) {
                    if (multiple) resolve([...files]);
                    else {
                        // Cargamos el archivo
                        const reader = new FileReader();

                        reader.onload = () => resolve(reader.result as string);
                        reader.readAsText(files[0]);
                    }
                } else reject();
                input.remove();
            };
            input.oncancel = () => reject();
            // Abrir el diálogo de selección de archivos
            input.click();
        });
    }

    /**
     * Guarda un archivo.
     *
     * @param name Nombre del archivo a guardar.
     * @param value Contenido del archivo a guardar.
     * @param type Tipo de archivo a guardar.
     */
    public static async saveFile(
        name: string,
        value: string,
        type?: string,
    ): Promise<void> {
        const fileBlob: Blob = new Blob([value], { type });
        const link: HTMLAnchorElement = document.createElement("a");

        link.href = URL.createObjectURL(fileBlob);
        link.download = name;
        // Esperamos un segundo para que se pueda descargar el archivo
        await new Promise((_) => setTimeout(_, 1000));
        // Descargamos el archivo
        link.click();
        URL.revokeObjectURL(link.href);
        link.remove();
    }

    /**
     * Amplia la cuadrícula.
     */
    public zoomIn(): void {
        if (this._zoom() >= 2) return;
        this._zoom.set(this._zoom() + 0.1);
    }

    /**
     * Reduce la cuadrícula.
     */
    public zoomOut(): void {
        if (this._zoom() <= 0.5) return;
        this._zoom.set(this._zoom() - 0.1);
    }

    /**
     * Restablece la ampliación de la cuadrícula.
     */
    public resetZoom(): void {
        this._zoom.set(1);
    }
}
