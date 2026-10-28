import { Injectable } from "@angular/core";
import { TensorflowModels } from "@models/cyber-shield";
import { ConfigService } from "@services/config.service";
import { io, LayersModel, loadLayersModel } from "@tensorflow/tfjs";
import { parseModelScript } from "@utils/parse_script";
import { loadZip } from "@utils/zip";
import { toast } from "ngx-sonner";
import { BehaviorSubject, Observable } from "rxjs";

/**
 * Clase que permite gestionar los modelos de inteligencia artificial de la aplicación.
 */
@Injectable()
export class ModelsService {
    /** Instancia única de la clase. */
    private static _instance: ModelsService;
    /** Instancia única de la clase. */
    public static get instance(): ModelsService {
        return ModelsService._instance;
    }
    /** Modelos cargados. */
    private _models?: TensorflowModels;
    /** Observable para emitir los modelos cargados. */
    private readonly _modelsSubject: BehaviorSubject<
        TensorflowModels | undefined
    >;
    /** Modelos cargados. */
    public get models(): TensorflowModels | undefined {
        return this._models;
    }
    /** Mostrar los modelos como un observable. */
    public get models$(): Observable<TensorflowModels | undefined> {
        return this._modelsSubject.asObservable();
    }

    /** Constructor privado para evitar instanciación externa */
    private constructor(readonly config: ConfigService) {
        // Cargar los modelos desde el localStorage
        const models = localStorage.getItem("models")?.split(",");

        if (models && models.length > 0) {
            Promise.all(
                models.map((id) =>
                    loadLayersModel(`localstorage://${id}_model`),
                ),
            ).then((tensorflowModels) => {
                this._models = models.map((id, index) => {
                    const model = tensorflowModels[index];

                    // Cargar la función de analisis
                    const scriptPlain = localStorage.getItem(`${id}_script`)!;
                    const script = parseModelScript(scriptPlain);

                    return {
                        id,
                        name: model.name,
                        model,
                        script,
                    };
                });
                this._modelsSubject.next(this._models);
            });
        }
        this._modelsSubject = new BehaviorSubject<TensorflowModels | undefined>(
            this._models,
        );
    }

    /**
     * Método estático para inicializar la clase.
     */
    public static init(config: ConfigService): ModelsService {
        if (!ModelsService.instance)
            ModelsService._instance = new ModelsService(config);
        return ModelsService.instance;
    }

    /**
     * Carga los modelos desde una lista de archivos.
     *
     * @param files Lista de archivos a cargar.
     */
    private async _load(files: File[]): Promise<void> {
        const models: TensorflowModels = [];

        for (const file of files) {
            const [jsonFile, binFiles, scriptFile] = await loadZip(file);

            // Creacion del modelo
            const model: LayersModel = await loadLayersModel(
                io.browserFiles([jsonFile, ...binFiles]),
            );

            // Cargar la función de analisis
            const scriptPlain = await scriptFile.text();
            const script = parseModelScript(scriptPlain);

            // Metadatos del modelo
            const id = model.name.toLowerCase().replace(/\s+/g, "_");
            const name = model.name;

            // Guardar el modelo
            models.push({ id, name, model, script });

            // Guardar en localStorage
            model.save(`localstorage://${id}_model`);
            localStorage.setItem(`${id}_script`, scriptPlain);
        }

        this._models = models;
        // Notificar a los observadores que la biblioteca ha cambiado
        this._modelsSubject.next(this._models);
        // Guardar los id de los modelos en el localStorage
        localStorage.setItem("models", models.map(({ id }) => id).join(","));
    }

    /**
     * Cargar los modelos desde archivos.
     */
    public loadFromFile(): void {
        toast.promise(
            ConfigService.openFile(".zip", true).then((val) => this._load(val)),
            {
                loading: this.config.translate.instant("MODELS_LOADING"),
                success: () => this.config.translate.instant("MODELS_LOADED"),
                error: (err) => {
                    console.error(err);
                    return this.config.translate.instant("MODELS_NOT_LOADED");
                },
            },
        );
    }

    /**
     * Elimina los modelos cargados.
     */
    public deleteFile(): void {
        // Eliminar los modelos del localStorage
        for (const model of this._models ?? []) {
            io.removeModel(`localstorage://${model.id}_model`);
            localStorage.removeItem(`${model.id}_script`);
        }
        localStorage.removeItem("models");
        this._models = undefined;
        // Notificar a los observadores que la biblioteca se ha eliminado
        this._modelsSubject.next(this._models);
        toast.success(this.config.translate.instant("MODELS_DELETED"));
    }
}
