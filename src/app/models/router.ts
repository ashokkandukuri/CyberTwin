import { Connection, ConnectionStatus } from "@models/connection";
import { Device } from "@models/device";
import { Node, NodeType } from "@models/node";
import { Packet } from "@models/packet";
import { Position } from "@models/position";

/** Clase que representa una tabla ARP de un router. */
class ARPTable {
    /** Tabla de direcciones ARP */
    private _table: Map<string, Connection>;
    /** Obtiene las conexiones de la tabla ARP */
    public get connections(): Connection[] {
        return [...this._table.values()];
    }

    /** Constructor de la tabla ARP */
    public constructor() {
        this._table = new Map<string, Connection>();
    }

    /**
     * Obtiene un elemento de la tabla ARP.
     *
     * @param ip Dirección IP a buscar.
     */
    public get(ip: string): Connection | undefined {
        return this._table.get(ip);
    }

    /**
     * Añade una dirección IP a la tabla ARP.
     *
     * @param ip IP a añadir
     * @param connection Conexión asociada a la IP
     */
    public add(ip: string, connection: Connection): void {
        this._table.set(ip, connection);
    }

    /**
     * Elimina una dirección IP de la tabla ARP.
     *
     * @param ip IP a eliminar
     * @returns Si la dirección IP fue eliminada.
     */
    public remove(ip: string): boolean {
        return this._table.delete(ip);
    }

    /**
     * Comprueba si una dirección IP está en la tabla ARP.
     *
     * @param ip IP a comprobar
     * @returns Si la dirección IP está en la tabla ARP.
     */
    public has(ip: string): boolean {
        return this._table.has(ip);
    }

    /**
     * Limpia la tabla ARP.
     */
    public clear(): void {
        this._table.clear();
    }

    /**
     * Obtiene el tamaño de la tabla ARP.
     */
    public size(): number {
        return this._table.size;
    }
}

/** Clase que representa un servidor DHCP. */
class DHCPServer {
    /** Conjunto de IPs disponibles */
    private _availableIPs: Set<string>;
    /** Mapa de IPs asignadas, MAC -> IP */
    private _assignedIPs: Map<string, string>;
    /** Obtiene las IPs asignadas */
    public get leasedIPs(): Map<string, string> {
        return { ...this._assignedIPs };
    }

    /**
     * Constructor de la clase DHCPServer.
     *
     * @param subnet Subred de donde se obtendrán las IPs
     * @param start IP inicial del rango
     * @param end IP final del rango
     */
    public constructor(subnet: string, start: number, end: number) {
        this._availableIPs = new Set();
        this._assignedIPs = new Map();

        for (let i = start; i <= end; i++) {
            this._availableIPs.add(`${subnet}.${i}`);
        }
    }

    /**
     * Asigna una IP a un dispositivo.
     *
     * @param mac Dirección MAC del dispositivo
     * @returns Dirección IP asignada
     */
    public requestIP(mac: string): string | null {
        if (this._assignedIPs.has(mac)) {
            return this._assignedIPs.get(mac)!;
        }

        const ip = this._availableIPs.values().next().value;

        if (!ip) return null;

        this._availableIPs.delete(ip);
        this._assignedIPs.set(mac, ip);
        return ip;
    }

    /**
     * Libera una IP asignada.
     *
     * @param mac Dirección MAC del dispositivo
     */
    public releaseIP(mac: string): void {
        const ip = this._assignedIPs.get(mac);

        if (ip) {
            this._assignedIPs.delete(mac);
            this._availableIPs.add(ip);
        }
    }

    /**
     * Registra una IP estática para un dispositivo.
     *
     * @param mac Dirección MAC del dispositivo
     * @param ip Dirección IP estática
     */
    public registerFixedIP(mac: string, ip: string): void {
        // TODO: Check if the IP exists in the available IPs
        this._availableIPs.delete(ip);
        this._assignedIPs.set(mac, ip);
    }
}

/** Clase que representa un router dentro de la red. */
export class Router extends Node {
    /** Tabla de direcciones ARP */
    private _arpTable: ARPTable;
    /** Servidor DHCP */
    private _dhcpServer: DHCPServer;
    /** Obtiene las conexiones del router */
    public get connections(): Connection[] {
        return this._arpTable.connections;
    }
    public override get connected(): boolean {
        return this.connections.length > 0;
    }
    public override get communicating(): boolean {
        return this.connections.some(
            (connection) => connection.status !== ConnectionStatus.IDLE,
        );
    }

    /**
     * Constructor de la clase Router.
     *
     * @param name Nombre del router
     * @param position Posición inicial del router
     */
    public constructor(name: string, position?: Position) {
        super(name, NodeType.ROUTER, position);
        this.init(undefined, "192.168.0.1");
        this._arpTable = new ARPTable();
        this._dhcpServer = new DHCPServer("192.168.0", 2, 254);
    }

    /**
     * Reenvía un paquete a través de la red.
     *
     * @param packet Paquete a reenviar.
     */
    private _forwardPacket(packet: Packet): void {
        const connection = this._arpTable.get(packet.dstIP);

        if (connection) {
            // Log de tráfico
            this.logTraffic(packet);
            // Generar un nuevo paquete con el TTL decrementado
            packet = { ...packet, ttl: (packet.ttl ?? 1) - 1 };
            // Reenviar el paquete al dispositivo correspondiente si el TTL es mayor a 0
            if (packet.ttl > 0) connection.spreadPacket(packet);
        } else
            throw new Error(
                `Impossible to forward the packet ${JSON.stringify(packet, null, 2)}, destination IP not found`,
            );
    }

    /**
     * Acepta una conexión entrante.
     *
     * @param node Nodo que intenta conectarse.
     * @param connection Conexión a establecer.
     * @returns Tupla con la dirección MAC y la conexión.
     */
    public acceptConnection(
        node: Node,
        connection?: Connection,
    ): [string, Connection] | null {
        // Si el dispositivo tiene una IP fija, registrarla en el servidor DHCP, si no, asignar una IP dinámica
        if (node.ip) this._dhcpServer.registerFixedIP(node.mac, node.ip);

        const ip: string | null =
            node.ip ?? this._dhcpServer.requestIP(node.mac);

        // Si no hay IPs disponibles, no se puede establecer la conexión
        if (!ip) return null;

        // Se crea una conexión entre el router y el dispositivo
        if (!connection) connection = new Connection(this, node);

        // Añadir la ip y la conexión a la tabla ARP
        this._arpTable.add(ip, connection);
        return [ip, connection];
    }

    /**
     * Elimina una conexión de la tabla ARP.
     *
     * @param node Nodo a desconectar.
     * @returns Si la conexión fue eliminada.
     */
    public removeConnection(node: Node): boolean {
        const connection = this._arpTable.get(node.ip ?? "");

        if (!connection) return false;
        this._arpTable.remove(node.ip ?? "");
        this._dhcpServer.releaseIP(node.mac);
        return true;
    }

    /**
     * Elimina todas las conexiones de la tabla ARP.
     *
     * @returns Si las conexiones fueron eliminadas.
     */
    public removeAllConnections(): boolean {
        for (const connection of this._arpTable.connections) {
            if (connection.node1 instanceof Device)
                connection.node1.disconnect(this);
            else if (connection.node2 instanceof Device)
                connection.node2.disconnect(this);
        }
        return this._arpTable.size() === 0;
    }

    public override sendPacket(packet: Packet): void {
        // Enviar el paquete al dispositivo correspondiente
        this._forwardPacket(packet);
    }

    public override receivePacket(packet: Packet): void {
        if (packet.dstIP === this.ip) {
            // Log de tráfico
            this.logTraffic(packet);
            // Interceptar el paquete
            this.interceptor.intercept(packet);
        } else this._forwardPacket(packet);
    }

    public static override fromObject(object: any): Router {
        return new Router(object.name, object.position).init(
            object.mac,
            object.ip,
            object.traffic,
        ) as Router;
    }

    public override toObject(): any {
        const traffic = this.traffic;

        return {
            name: this.name,
            mac: this.mac,
            ip: this.ip,
            position: { ...this.position },
            traffic: traffic.length > 0 ? traffic : undefined,
        };
    }
}
