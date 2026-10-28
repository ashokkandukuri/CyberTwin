import { Injectable } from "@angular/core";
import { ConfigService } from "@services/config.service";
import { parseLibraryScript } from "@utils/parse_script";
import { toast } from "ngx-sonner";
import { BehaviorSubject, Observable } from "rxjs";

/**
 * Clase que permite gestionar las bibliotecas de la aplicación.
 */
@Injectable()
export class LibraryService {
    /** Instancia única de la clase. */
    private static _instance: LibraryService;
    /** Instancia única de la clase. */
    public static get instance(): LibraryService {
        return LibraryService._instance;
    }
    /** Bibliotecas almacenada. */
    private _library?: Function = undefined;
    /** Biblioteca almacenada. */
    public get library(): Function | undefined {
        return this._library;
    }
    /** Observable para emitir el estado actual de la biblioteca cargada. */
    private readonly _librarySubject: BehaviorSubject<Function | undefined> =
        new BehaviorSubject<Function | undefined>(undefined);
    /** Observable que notifica cada vez que se carga una biblioteca */
    public get library$(): Observable<Function | undefined> {
        return this._librarySubject.asObservable();
    }

    /**
     * Constructor del gestor de bibliotecas.
     */
    private constructor(readonly config: ConfigService) {
        // Cargar la biblioteca desde el localStorage
        const script = localStorage.getItem("library");

        if (script) this._load(script);
    }

    /**
     * Método estático para inicializar la clase.
     */
    public static init(config: ConfigService): LibraryService {
        if (!LibraryService.instance)
            LibraryService._instance = new LibraryService(config);
        return LibraryService.instance;
    }

    /**
     * Carga una biblioteca externa desde un string.
     *
     * @param script Contenido de la biblioteca a cargar.
     */
    private _load(script: string): void {
        this._library = parseLibraryScript(script);
        // Notificar a los observadores que la biblioteca ha cambiado
        this._librarySubject.next(this._library);
        // Guardar la biblioteca en el localStorage
        localStorage.setItem("library", script);
    }

    /**
     * Carga una biblioteca externa desde un archivo.
     */
    public loadFromFile(): void {
        toast.promise(
            ConfigService.openFile(".js").then((val) => this._load(val)),
            {
                loading: this.config.translate.instant("LIBRARY_LOADING"),
                success: () => this.config.translate.instant("LIBRARY_LOADED"),
                error: (err) => {
                    console.error(err);
                    return this.config.translate.instant("LIBRARY_NOT_LOADED");
                },
            },
        );
    }

    /**
     * Elimina la biblioteca externa cargada.
     */
    public deleteFile(): void {
        // Eliminar la biblioteca del localStorage
        localStorage.removeItem("library");
        this._library = undefined;
        // Notificar a los observadores que la biblioteca se ha eliminado
        this._librarySubject.next(this._library);
        toast.success(this.config.translate.instant("LIBRARY_DELETED"));
    }
}
