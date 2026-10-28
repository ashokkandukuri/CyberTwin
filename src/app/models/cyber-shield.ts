import { Packet } from "@models/packet";
import { ModelsService } from "@services/models.service";
import { StateService } from "@services/state.service";
import * as tf from "@tensorflow/tfjs";
import { LayersModel } from "@tensorflow/tfjs";

/**
 * Estado del cyber shield.
 */
export enum CyberShieldState {
    /** Desactivado */
    Disabled = "disabled",
    /** Esperando */
    Waiting = "waiting",
    /** Seguro */
    Safe = "safe",
    /** Ataque */
    Attack = "attack",
}

/**
 * Modelos que se pueden usar.
 */
export type Models = Model[];

/**
 * Modelo de redes neuronal.
 */
export interface Model {
    /** Identificador del modelo */
    id: string;
    /** Nombre del modelo */
    name: string;
}

/**
 * Modelos de Tensorflow.
 */
export type TensorflowModels = TensorflowModel[];

/**
 * Modelo de Tensorflow.
 */
export interface TensorflowModel extends Model {
    /** Modelo de Tensorflow */
    model: LayersModel;
    /** Script del modelo */
    script: Function;
}

/**
 * Modelo compilado de Tensorflow.
 */
export interface CompiledTensorflowModel extends Model {
    model: LayersModel;
    analyze: (packet: Packet) => any;
}

/**
 * Modelos de redes neuronales.
 */
export class CyberShield {
    /** Estado del cyber shield. */
    private _state: CyberShieldState;
    /** Estado del cyber shield. */
    public get state(): CyberShieldState {
        return this._state;
    }
    /** Estado de activación del cyber shield. */
    public get enabled(): boolean {
        return (
            this._state !== CyberShieldState.Disabled &&
            this._models !== undefined
        );
    }
    /** Estado de activación del cyber shield. */
    @StateService.SetState
    public set enabled(value: boolean) {
        this._state =
            this._models !== undefined && value
                ? CyberShieldState.Waiting
                : CyberShieldState.Disabled;
    }
    /** Modelos de redes neuronales. */
    private _models?: { [model: string]: CompiledTensorflowModel };
    /** Modelos de redes neuronales. */
    public get models(): Readonly<Models> {
        return this._models
            ? Object.values(this._models).map(({ id, name }) => ({ id, name }))
            : [];
    }
    /** Id del modelo que se esta usando. */
    private _model?: string;
    /** Modelo que se esta usando. */
    public get model(): string | undefined {
        return this._model;
    }
    /** Modelo que se esta usando. */
    @StateService.SetState
    public set model(model: string | undefined) {
        if (model && this._models) this._model = model;
        else this._model = undefined;
        this._state = CyberShieldState.Waiting;
    }

    /**
     * Crea una instancia de CyberShield.
     */
    public constructor() {
        this._state = CyberShieldState.Disabled;
        this._model = undefined;
        this._models = undefined;

        // Cargar los modelos de Tensorflow
        ModelsService.instance.models$.subscribe((models) =>
            this.loadModels(models),
        );
    }

    /**
     * Cargar los modelos.
     *
     * @param models Modelos a cargar
     */
    public loadModels(models?: TensorflowModels): void {
        if (models) {
            this._models = {};
            for (const { id, name, model, script } of models)
                this._models[id] = {
                    id,
                    name,
                    model,
                    analyze: script(tf, model)["analyze"],
                };
        } else {
            this._state = CyberShieldState.Disabled;
            this._models = undefined;
        }
    }

    /**
     * Se encarga de analizar el paquete con el modelo.
     *
     * @param packet Paquete a analizar
     * @returns Resultado del analisis
     */
    public analyze(packet: Packet): void {
        try {
            if (this.enabled) {
                const model = this._models?.[this._model ?? ""];

                if (model) {
                    const res = model.analyze(packet);

                    if (typeof res === "boolean") {
                        if (res) this._state = CyberShieldState.Attack;
                        else this._state = CyberShieldState.Safe;
                    } else this._state = CyberShieldState.Waiting;
                }
            }
        } catch (error) {
            console.error(error);
        }
    }

    /**
     * Convierte el cyber shield a un objeto plano.
     *
     * @returns Objeto plano con los datos del cyber shield.
     */
    public toObject(): any {
        return {
            enabled: this._state !== CyberShieldState.Disabled,
            model: this.model,
        };
    }

    /**
     * Convierte un objeto plano en un cyber shield.
     *
     * @param object Objeto plano a convertir.
     * @returns CyberShield convertido.
     */
    public static fromObject(object: any): CyberShield {
        const cyberShield = new CyberShield();

        if (object.enabled) cyberShield._state = CyberShieldState.Waiting;
        if (object.model) cyberShield._model = object.model;
        return cyberShield;
    }
}
