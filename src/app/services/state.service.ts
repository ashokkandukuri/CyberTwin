import { Injectable } from "@angular/core";
import { BehaviorSubject, debounceTime, Observable, ReplaySubject } from "rxjs";

/** Máximos estados a almacenar. */
const MAX_STATES = 40;

/**
 * Clase que permite gestionar los estados de la aplicación.
 */
@Injectable()
export class StateService {
    /** Instancia única de la clase. */
    private static _instance: StateService;
    /** Instancia única de la clase. */
    public static get instance(): StateService {
        return StateService._instance;
    }
    /** Anotación para usar el gestor de estados en una clase. */
    public static readonly UseState = <T extends { new (...args: any[]): {} }>(
        constructor: T,
    ) => {
        return class extends constructor {
            constructor(...args: any[]) {
                super(...args);

                // Escuchar el estado de la aplicación
                (this as any).fromObject(StateService.instance.state);
                StateService.instance.state$.subscribe((state) =>
                    (this as any).fromObject(state),
                );
                // Guardar un nuevo estado
                StateService.instance._requestStateSubject
                    .pipe(debounceTime(500))
                    .subscribe(() =>
                        StateService.instance.setState(
                            (this as any).toObject(),
                            false,
                        ),
                    );
            }
        };
    };
    /** Anotación para requerir un cambio de estado. */
    public static readonly SetState: Function = (
        target: Object,
        propertyKey: string,
        descriptor: PropertyDescriptor,
    ) => {
        const { value, set } = descriptor;

        if (value)
            descriptor.value = function (...args: any[]) {
                const result = value.apply(this, args);

                StateService.instance._requestStateSubject.next();
                return result;
            };
        else if (set)
            descriptor.set = function (value: any) {
                set.apply(this, [value]);
                StateService.instance._requestStateSubject.next();
            };
        else
            throw new Error(
                "The setState decorator can only be used on methods or properties that change the state.",
            );
    };
    /** Lista de estados almacenados. */
    private _states: any[];
    /** Índice del estado actual. */
    private _index: number;
    /** Estado actual. */
    public get state(): any {
        return this._states[this._index];
    }
    /** Observable para requerir un cambio de estado. */
    private readonly _requestStateSubject: ReplaySubject<void>;
    /** Observable para emitir el estado actual de la aplicación. */
    private readonly _stateSubject: BehaviorSubject<any>;
    /** Observable que notifica cada vez que se cambia de estado la aplicación. */
    public get state$(): Observable<Function | undefined> {
        return this._stateSubject.asObservable();
    }
    /**
     * Función que permite requerir un cambio de estado.
     */
    /** Permite obtener si se puede deshacer un cambio */
    public get canUndo(): boolean {
        return this._index > 0;
    }
    /** Permite obtener si se puede rehacer un cambio */
    public get canRedo(): boolean {
        return this._index < this._states.length - 1;
    }

    /**
     * Constructor del gestor de estados.
     */
    private constructor() {
        const state = sessionStorage.getItem("state");

        if (state) this._states = [JSON.parse(state)];
        else this._states = [{}];
        this._index = 0;
        this._requestStateSubject = new ReplaySubject<void>(1);
        this._stateSubject = new BehaviorSubject<any>(
            this._states[this._index],
        );
    }

    /**
     * Método estático para inicializar la clase.
     */
    public static init(): StateService {
        if (!StateService.instance) StateService._instance = new StateService();
        return StateService.instance;
    }

    /**
     * Establece un nuevo estado y lo limita a cierto número de elementos.
     *
     * @param state Nuevo estado a almacenar.
     */
    public setState(state: any, notify: boolean = true) {
        // Eliminar estados futuros
        this._states = this._states.slice(0, this._index + 1);
        // Agregamos el nuevo estado
        this._states.push(state);
        this._index++;
        // Eliminamos el más antiguo en caso de que se exceda el límite
        if (this._states.length > MAX_STATES) {
            this._states.shift();
            this._index--;
        }
        // Notificamos el cambio
        if (notify) this._stateSubject.next(this.state);
        sessionStorage.setItem("state", JSON.stringify(this.state));
    }

    /**
     * Reemplaza el estado actual por uno nuevo.
     *
     * @param state Nuevo estado a almacenar.
     */
    public replaceState(state: any, notify: boolean = true) {
        // Reemplazamos el estado actual
        this._states[this._index] = state;
        // Notificamos el cambio
        if (notify) this._stateSubject.next(this.state);
        sessionStorage.setItem("state", JSON.stringify(this.state));
    }

    /**
     * Deshace el último cambio.
     */
    public undo(notify: boolean = true) {
        if (this.canUndo) {
            // Decrementamos el índice
            this._index--;
            // Notificamos el cambio
            if (notify) this._stateSubject.next(this.state);
            sessionStorage.setItem("state", JSON.stringify(this.state));
        }
    }

    /**
     * Rehace el último cambio
     */
    public redo(notify: boolean = true) {
        if (this.canRedo) {
            // Incrementamos el índice
            this._index++;
            // Notificamos el cambio
            if (notify) this._stateSubject.next(this.state);
            sessionStorage.setItem("state", JSON.stringify(this.state));
        }
    }

    /**
     * Reinicia el gestor de estados.
     */
    public reset(notify: boolean = true) {
        // Limpiamos la lista de estados y el índice
        this._states = [{}];
        this._index = 0;
        // Notificamos el cambio
        if (notify) this._stateSubject.next(this.state);
        sessionStorage.setItem("state", JSON.stringify(this.state));
    }
}
