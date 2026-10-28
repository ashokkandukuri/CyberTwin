import { FlowGenerator } from "@models/flow-generator";
import { FlowInterceptor } from "@models/flow-interceptor";
import { Packet } from "@models/packet";
import { PhantomAttacker } from "@models/phantom-attacker";
import { Position } from "@models/position";
import { CANVAS_SIZE } from "@services/config.service";
import { LibraryService } from "@services/library.service";
import { StateService } from "@services/state.service";

/* Expresión regular para validar una dirección MAC */
const MAC_REGEX: RegExp = /^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$/;
/* Expresión regular para validar una dirección IP */
const IP_REGEX: RegExp = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;

/**
 * Enum que representa los diferentes tipos de nodos en el simulador IoT.
 */
export enum NodeType {
    ROUTER = "router",
    COMPUTER = "computer",
    IOT = "iot",
}

export namespace NodeType {
    /**
     * Lista de tipos de nodos.
     */
    export const Types: ReadonlyArray<NodeType> = [
        NodeType.ROUTER,
        NodeType.COMPUTER,
        NodeType.IOT,
    ];

    /**
     * Lista de tipos de nodos que pueden ser routers.
     */
    export const RouterTypes: ReadonlyArray<NodeType> = [NodeType.ROUTER];

    /**
     * Lista de tipos de nodos que pueden ser dispositivos.
     */
    export const DeviceTypes: ReadonlyArray<NodeType> = [
        NodeType.COMPUTER,
        NodeType.IOT,
    ];

    /**
     * Lista de tipos de nodos que pueden ser atacantes.
     */
    export const AttackerTypes: ReadonlyArray<NodeType> = [NodeType.COMPUTER];

    /**
     * Devuelve una lista de tipos de nodos según el tipo de nodo proporcionado.
     *
     * @param type Tipo de nodo.
     * @returns Lista de tipos de nodos.
     */
    export const getTypes = (type?: NodeType): ReadonlyArray<NodeType> => {
        switch (type) {
            case NodeType.ROUTER:
                return RouterTypes;
            case NodeType.COMPUTER:
            case NodeType.IOT:
                return DeviceTypes;
            default:
                return Types;
        }
    };

    /**
     * Convierte un string a un tipo de nodo.
     *
     * @param type String que representa un tipo de nodo.
     * @returns Tipo de nodo.
     */
    export const toString = (type: NodeType): string => {
        switch (type) {
            case NodeType.ROUTER:
                return "ROUTER";
            case NodeType.COMPUTER:
                return "COMPUTER";
            case NodeType.IOT:
                return "IOT_DEVICE";
        }
    };
}

/**
 * Clase abstracta que representa un nodo en el simulador IoT.
 */
export abstract class Node {
    /** Dirección MAC del nodo */
    private _mac: string;
    /** Dirección MAC del nodo */
    public get mac(): string {
        return this._mac;
    }
    /** Dirección IP del nodo */
    private _ip?: string;
    /** Dirección IP del nodo */
    public get ip(): string | undefined {
        return this._ip;
    }
    /** Dirección IP del nodo */
    @StateService.SetState
    protected set ip(value: any) {
        if (
            value !== undefined &&
            (typeof value !== "string" || !IP_REGEX.test(value))
        )
            throw new Error("Invalid IP address");

        this._ip = value;
    }
    /** Nombre del nodo */
    private _name: string;
    /** Nombre del nodo */
    public get name(): string {
        return this._name;
    }
    /** Nombre del nodo */
    @StateService.SetState
    public set name(value: string) {
        if (this._name === value) return;

        this._name = value;
    }
    /** Tipo de nodo */
    private _type: NodeType;
    /** Tipo de nodo */
    public get type(): NodeType {
        return this._type;
    }
    /** Tipo de nodo */
    @StateService.SetState
    public set type(value: any) {
        if (this._type === value) return;
        if (!NodeType.Types.includes(value))
            throw new Error("Invalid node type");
        if (this._type === NodeType.ROUTER && value !== NodeType.ROUTER)
            throw new Error("Cannot change the type of a router");
        if (this._type !== NodeType.ROUTER && value === NodeType.ROUTER)
            throw new Error("Cannot change the type of a device to a router");
        if (NodeType.AttackerTypes.includes(value))
            this._generator = new PhantomAttacker(this, this.interceptor);
        else if (this._generator instanceof PhantomAttacker)
            this._generator = new FlowGenerator(this, this.interceptor);
        this._generator.loadLibrary(this._library);
        this._type = value;
    }
    /** Biblioteca externa */
    private _library?: Function;
    /** Interceptor de flujo de red */
    protected readonly interceptor: FlowInterceptor;
    /** Generador de flujos de red */
    private _generator: FlowGenerator;
    /** Generador de flujos de red */
    public get generator(): FlowGenerator {
        return this._generator;
    }
    /** Historial de tráfico del nodo */
    private _traffic: Packet[];
    /** Historial de tráfico del nodo */
    public get traffic(): ReadonlyArray<Packet> {
        return this._traffic.map((e) => ({ ...e }));
    }
    /** Posición del nodo */
    private _position: Position;
    /** Posición del nodo */
    public get position(): Position {
        return { ...this._position };
    }
    /** Indica si el nodo está conectado */
    public abstract get connected(): boolean;
    /** Indica si el nodo está comunicando */
    public abstract get communicating(): boolean;

    /**
     * Crea una instancia de la clase Node.
     *
     * @param name Nombre del nodo.
     * @param type Tipo de nodo.
     * @param position Posición del nodo.
     */
    protected constructor(
        name: string,
        type: NodeType,
        position: Position = { x: 0, y: 0 },
    ) {
        this._mac = this._generateMac();
        this._ip = undefined;
        this._name = name;
        this._type = type;
        this.interceptor = new FlowInterceptor(this);
        this._generator = NodeType.AttackerTypes.includes(type)
            ? new PhantomAttacker(this, this.interceptor)
            : new FlowGenerator(this, this.interceptor);
        this._traffic = [];
        this._position = {
            x: Math.min(
                Math.max(position.x, -CANVAS_SIZE / 2),
                CANVAS_SIZE / 2,
            ),
            y: Math.min(
                Math.max(position.y, -CANVAS_SIZE / 2),
                CANVAS_SIZE / 2,
            ),
        };

        // Cargar biblioteca y obtener cambios
        LibraryService.instance.library$.subscribe((library) =>
            this.loadLibrary(library),
        );
    }

    /**
     * Inicializa el nodo con una dirección MAC, IP y tráfico.
     *
     * @param mac Dirección MAC del nodo.
     * @param ip Dirección IP del nodo.
     * @param traffic Historial de tráfico del nodo.
     * @returns Instancia del nodo.
     */
    protected init(mac?: string, ip?: string, traffic?: Packet[]): Node {
        if (mac && !MAC_REGEX.test(mac)) throw new Error("Invalid MAC address");
        if (mac) this._mac = mac;
        if (ip && !IP_REGEX.test(ip)) throw new Error("Invalid IP address");
        if (ip) this._ip = ip;
        if (traffic) this._traffic = traffic.map((e) => ({ ...(e as Packet) }));
        return this;
    }

    /**
     * Genera una dirección MAC aleatoria.
     *
     * @returns Dirección MAC aleatoria.
     */
    private _generateMac(): string {
        return "XX:XX:XX:XX:XX:XX".replace(/X/g, () =>
            Math.floor(Math.random() * 16).toString(16),
        );
    }

    /**
     * Carga una biblioteca externa.
     *
     * @param library Biblioteca a cargar.
     */
    public loadLibrary(library?: Function): void {
        this._library = library ? library() : undefined;
        this.interceptor.loadLibrary(this._library);
        this.generator.loadLibrary(this._library);
    }

    /**
     * Envía un paquete al nodo.
     *
     * @param packet Paquete a enviar.
     */
    public abstract sendPacket(packet: Packet): void;

    /**
     * Recibe un paquete del nodo.
     *
     * @param packet Paquete recibido.
     */
    public abstract receivePacket(packet: Packet): void;

    /**
     * Registra un paquete en el historial de tráfico del nodo.
     *
     * @param packet Paquete a registrar en el historial de tráfico.
     */
    protected logTraffic(packet: Packet): void {
        this._traffic.push(packet);
    }

    /**
     * Limpia el historial de tráfico del nodo.
     */
    protected clearTraffic(): void {
        this._traffic = [];
    }

    /**
     * Mueve el nodo a una nueva posición.
     *
     * @param x Coordenada X de la nueva posición.
     * @param y Coordenada Y de la nueva posición.
     * @param relative Indica si el movimiento es relativo a la posición actual, por defecto es falso.
     */
    @StateService.SetState
    public move(x: number, y: number, relative: boolean = false): void {
        if (!relative && this._position.x === x && this._position.y === y)
            return;

        if (relative) {
            x = this._position.x + x;
            y = this._position.y + y;
        }
        this._position = {
            x: Math.min(Math.max(x, -CANVAS_SIZE / 2), CANVAS_SIZE / 2),
            y: Math.min(Math.max(y, -CANVAS_SIZE / 2), CANVAS_SIZE / 2),
        };
    }

    /**
     * Convierte un objeto plano en un nodo.
     *
     * @param object Objeto plano a convertir.
     * @returns Nodo convertido.
     */
    public static fromObject(object: any): Node {
        throw new Error("Method not implemented");
    }

    /**
     * Convierte el nodo en un objeto plano.
     *
     * @returns Nodo convertido en objeto plano.
     */
    public abstract toObject(): any;
}
