import { Node } from "@models/node";
import { Packet } from "@models/packet";
import { StateService } from "@services/state.service";
import { randomInt, randomMeanStd } from "@utils/random";
import { CyberShield } from "./cyber-shield";

/**
 * Enumeración de los estados de transmisión de la conexión.
 */
export enum ConnectionStatus {
    IDLE,
    FORWARD,
    REVERSE,
}

/**
 * Representa una conexión entre un dispositivo y un router. A esta conexión se le puede asignar una latencia y permite comunicar ambos dispositivos.
 */
export class Connection {
    /** Cola de paquetes */
    private _queue: Packet[];
    /** Indica si la conexión está procesando un paquete */
    private _processing: boolean;
    /** Router al que se conecta el dispositivo */
    public readonly node1: Node;
    /** Nodo para el que se establece la conexión */
    public readonly node2: Node;
    /** Latencia de la conexión */
    private _latency: number;
    /** Latencia de la conexión. */
    public get latency(): number {
        return this._latency;
    }
    /** Latencia de la conexión. */
    @StateService.SetState
    public set latency(value: number) {
        if (value < 0) throw new Error("The latency cannot be negative");
        this._latency = value;
    }
    /** Variación de la latencia de la conexión */
    private _latencyVariation: number;
    /** Variación de la latencia de la conexión. */
    public get latencyVariation(): number {
        return this._latencyVariation;
    }
    /** Variación de la latencia de la conexión. */
    @StateService.SetState
    public set latencyVariation(value: number) {
        if (value < 0)
            throw new Error("The latency variation cannot be negative");
        this._latencyVariation = value;
    }
    /** Ancho de banda de la conexión. */
    private _bandwidth: number;
    /** Ancho de banda de la conexión. */
    public get bandwidth(): number {
        return this._bandwidth;
    }
    /** Ancho de banda de la conexión. */
    @StateService.SetState
    public set bandwidth(value: number) {
        if (value <= 0)
            throw new Error("The bandwidth cannot be negative or zero");
        this._bandwidth = value;
    }

    /**
     * Estado de la conexión.
     * - IDLE: La conexión está inactiva.
     * - FORWARD: La conexión está transmitiendo un paquete desde el nodo 1 al nodo 2.
     * - REVERSE: La conexión está transmitiendo un paquete desde el nodo 2 al nodo 1.
     */
    private _status: ConnectionStatus;
    public get status(): ConnectionStatus {
        return this._status;
    }
    /** Protector de flujo de red */
    private _cyberShield: CyberShield;
    /** Protector de flujo de red. */
    public get cyberShield(): CyberShield {
        return this._cyberShield;
    }

    /**
     * Crea una instancia de la clase Connection.
     *
     * @param node1 Primer nodo de la conexión, suele ser un router.
     * @param node2 Segundo nodo de la conexión, suele ser un dispositivo.
     * @param latency Latencia de la conexión, si no se especifica, se asigna un valor aleatorio entre 0 y 1000 ms.
     * @param latencyVariation Variación de la latencia de la conexión, si no se especifica, se asigna 0.
     * @param bandwidth Ancho de banda de la conexión, si no se especifica, se asigna un valor aleatorio entre 100 KB/s y 1 MB/s.
     * @param cyberShield Protector de flujo de red, si no se especifica, se asigna uno por defecto.
     */
    public constructor(
        node1: Node,
        node2: Node,
        latency?: number,
        latencyVariation?: number,
        bandwidth?: number,
        cyberShield?: CyberShield,
    ) {
        this._queue = [];
        this._processing = false;
        this.node1 = node1;
        this.node2 = node2;
        this._latency = latency ?? randomInt(0, 1000);
        this._latencyVariation = latencyVariation ?? 0;
        this._bandwidth = bandwidth ?? randomInt(100000, 1000000);
        this._status = ConnectionStatus.IDLE;
        this._cyberShield = cyberShield ?? new CyberShield();
    }

    /**
     * Procesa la cola de paquetes.
     */
    private async _processQueue(): Promise<void> {
        if (this._processing || this._queue.length === 0) return;

        this._processing = true;
        while (this._queue.length > 0) {
            const packet = this._queue.shift() as Packet;
            let reciver;

            if (packet.dstIP === this.node2.ip) {
                this._status = ConnectionStatus.FORWARD;
                reciver = this.node2;
            } else {
                this._status = ConnectionStatus.REVERSE;
                reciver = this.node1;
            }

            const latency = randomMeanStd(
                this._latency,
                this._latencyVariation,
            );
            const bandwidth = (packet.totalBytes / this._bandwidth) * 1000;

            await new Promise((resolve) =>
                setTimeout(resolve, latency + bandwidth),
            );
            // Analiza el paquete con el modelo
            this.cyberShield.analyze(packet);
            // Envia el paquete al receptor
            reciver.receivePacket(packet);
        }
        this._processing = false;
        this._status = ConnectionStatus.IDLE;
    }

    /**
     * Transmite un paquete desde el dispositivo al router o viceversa.
     *
     * @param packet Paquete a transmitir.
     */
    public spreadPacket(packet: Packet): void {
        this._queue.push(packet);
        this._processQueue();
    }

    /**
     * Convierte la conexión a un objeto plano.
     *
     * @returns Objeto plano con los datos de la conexión.
     */
    public toObject(): any {
        return {
            latency: this.latency,
            latencyVariation: this.latencyVariation,
            bandwidth: this.bandwidth,
            cyberShield: this.cyberShield.toObject(),
        };
    }

    /**
     * Convierte un objeto plano en una conexión.
     *
     * @param node1 Primer nodo de la conexión, suele ser un router.
     * @param node2 Segundo nodo de la conexión, suele ser un dispositivo.
     * @param object Objeto plano a convertir.
     * @returns Conexión convertida.
     */
    public static fromObject(
        node1: Node,
        node2: Node,
        object: any,
    ): Connection {
        return new Connection(
            node1,
            node2,
            object.latency,
            object.latencyVariation,
            object.bandwidth,
            CyberShield.fromObject(object.cyberShield),
        );
    }
}
