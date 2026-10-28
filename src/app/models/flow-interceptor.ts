import { Node } from "@models/node";
import {
    ICMPPacket,
    ICMPType,
    Packet,
    TCPFlags,
    TCPPacket,
    TransportProtocol,
} from "@models/packet";
import { BehaviorSubject, Observable } from "rxjs";

/**
 * Interceptor de flujo.
 */
export class FlowInterceptor {
    /** Observable para emitir los paquetes interceptados. */
    private readonly _intercept: BehaviorSubject<Packet | null> =
        new BehaviorSubject<Packet | null>(null);
    /** Observable para emitir los paquetes interceptados. */
    public get intercept$(): Observable<Packet | null> {
        return this._intercept;
    }
    /** Interceptor externo */
    private _externalInterceptor?: (packet: Packet) => any;

    /**
     * Crea un generador de flujos de red.
     *
     * @param node Nodo de red.
     */
    public constructor(private readonly node: Node) {}

    /**
     * Intercepta un paquete ICMP y realiza una acción en caso de ser necesario.
     *
     * @param packet Paquete ICMP.
     */
    private _interceptICMP(packet: ICMPPacket): void {
        switch (packet.type) {
            case ICMPType.ECHO_REQUEST:
                this.node.sendPacket(
                    Packet.ICMPEchoReply(
                        this.node.ip ?? "",
                        packet.srcIP,
                        packet.identifier,
                        packet.sequence,
                    ),
                );
                break;
            case ICMPType.ECHO_REPLY:
                break;
        }
    }

    /**
     * Itercepta un paquete TCP y realiza una acción en caso de ser necesario.
     *
     * @param packet Paquete TCP.
     */
    private _interceptTCP(packet: TCPPacket): void {
        switch (packet.tcpFlags) {
            case TCPFlags.SYN:
                this.node.sendPacket(
                    Packet.TCPSYNACK(
                        this.node.ip!,
                        packet.srcIP,
                        packet.dstPort!,
                        packet.srcPort!,
                        packet.sequence,
                    ),
                );
                break;
            case TCPFlags.SYN | TCPFlags.ACK:
                this.node.sendPacket(
                    Packet.TCPACK(
                        this.node.ip!,
                        packet.srcIP,
                        packet.dstPort!,
                        packet.srcPort!,
                        packet.sequence,
                        packet.ack,
                    ),
                );
                break;
            case TCPFlags.ACK:
                break;
        }
    }

    /**
     * Intercepta un paquete de red y realiza una acción en caso de ser necesario.
     *
     * @param packet Paquete de red.
     */
    public intercept(packet: Packet): void {
        if (this._externalInterceptor) {
            try {
                if (this._externalInterceptor({ ...packet }) !== undefined)
                    return;
            } catch (err) {
                console.error(err);
            }
        }
        this._intercept.next({ ...packet });
        switch (packet.transportProtocol) {
            case TransportProtocol.ICMP:
                this._interceptICMP(packet as ICMPPacket);
                break;
            case TransportProtocol.TCP:
                this._interceptTCP(packet as TCPPacket);
                break;
            case TransportProtocol.UDP:
                break;
        }
    }

    /**
     * Carga una biblioteca de funciones.
     *
     * @param library Biblioteca de funciones.
     */
    public loadLibrary(library: any | undefined): void {
        if (!library) {
            this._externalInterceptor = undefined;
            return;
        }

        const interceptor =
            Object.keys(library).find((e) => e === `intcp_${this.node.type}`) ??
            Object.keys(library).find((e) => e === "intcp");

        if (interceptor)
            this._externalInterceptor = (arg) =>
                library[interceptor](
                    {
                        mac: this.node.mac,
                        ip: this.node.ip,
                        name: this.node.name,
                        type: this.node.type as string,
                        send: (packet: Packet) => this.node.sendPacket(packet),
                    },
                    arg,
                );
    }
}
