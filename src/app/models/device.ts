import { Connection, ConnectionStatus } from "@models/connection";
import { Node, NodeType } from "@models/node";
import { Packet } from "@models/packet";
import { Position } from "@models/position";
import { Router } from "@models/router";

/**
 * Clase que representa un dispositivo en la red.
 */
export class Device extends Node {
    /* Conexión del dispositivo */
    private _connection?: Connection;
    public override get connected(): boolean {
        return this._connection !== undefined;
    }
    public override get communicating(): boolean {
        return (
            this._connection !== undefined &&
            this._connection.status !== ConnectionStatus.IDLE
        );
    }

    /**
     * Constructor de la clase Device.
     *
     * @param name Nombre del dispositivo.
     * @param type Tipo del dispositivo.
     * @param position Posición inicial del dispositivo.
     */
    public constructor(
        name: string,
        type: NodeType.COMPUTER | NodeType.IOT,
        position?: Position,
    ) {
        super(name, type, position);
    }

    /**
     * Conectar el dispositivo a un router.
     *
     * @param router Router al que se conectará el dispositivo.
     * @param connection Conexión a establecer.
     */
    public connect(router: Router, connection?: Connection): void {
        const result = router.acceptConnection(this, connection);

        if (!result) throw new Error(`${this.mac} could not connect to router`);

        const [ip, newConnection] = result;

        if (this.ip !== ip) this.ip = ip;
        this._connection = newConnection;
    }

    /**
     * Desconectar el dispositivo de un router.
     *
     * @param router Router al que se desconectará el dispositivo.
     */
    public disconnect(router: Router): void {
        const disconnected = router.removeConnection(this);

        if (disconnected) {
            this._connection = undefined;
            this.ip = undefined;
        }
    }

    public override sendPacket(packet: Packet): void {
        if (this._connection === undefined)
            throw new Error(`${this.mac} is not connected to a router`);

        // Log de tráfico
        this.logTraffic(packet);
        // Enviar el paquete a través de la conexión
        this._connection.spreadPacket(packet);
    }

    public override receivePacket(packet: Packet): void {
        if (this.ip !== packet.dstIP)
            throw new Error(`Packet is not addressed to ${this.mac}`);

        // Log de tráfico
        this.logTraffic(packet);
        // Interceptar el paquete
        this.interceptor.intercept(packet);
    }

    public static override fromObject(object: any): Device {
        return new Device(object.name, object.type, object.position).init(
            object.mac,
            object.ip,
            object.traffic,
        ) as Device;
    }

    public override toObject() {
        const traffic = this.traffic;

        return {
            name: this.name,
            mac: this.mac,
            ip: this.ip,
            type: this.type,
            position: this.position,
            connection: this._connection?.toObject(),
            traffic: traffic.length > 0 ? traffic : undefined,
        };
    }
}
