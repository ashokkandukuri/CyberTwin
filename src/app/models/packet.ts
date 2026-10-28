/**
 * Enum que representa varios protocolos de capa de transporte con sus números de protocolo.
 */
export enum TransportProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
}

/**
 * Enum que representa varios protocolos de capa de aplicación con sus números de puerto estándar.
 */
export enum ApplicationProtocol {
    FTP = 20,
    SMTP = 25,
    DNS = 53,
    DHCP = 67,
    HTTP = 80,
    HTTPS = 443,
}

/**
 * Modelo que representa un paquete de red.
 */
export interface Packet {
    // Direcciones y puertos
    /* Dirección IP de origen */
    srcIP: string;
    /* Puerto de origen */
    srcPort?: number;
    /* Dirección IP de destino */
    dstIP: string;
    /* Puerto de destino */
    dstPort?: number;

    // Protocolos
    /* Protocolo de capa de transporte */
    transportProtocol: TransportProtocol;
    /* Protocolo de capa de aplicación */
    applicationProtocol?: ApplicationProtocol;

    // Datos y tamaño
    /* Datos del paquete */
    payload?: string;
    /* Tamaño del paquete en bytes */
    totalBytes: number;
    /* Tamaño de las cabeceras */
    headerSize: number;
    /* Tamaño de la carga útil (sin cabeceras) */
    payloadSize: number;

    // Información temporal
    /* Momento en que se generó el paquete */
    timestamp: Date;
    /* Tiempo de vida del paquete */
    ttl: number;
}

/**
 * Tipo de paquete ICMP.
 */
export enum ICMPType {
    ECHO_REPLY = 0,
    ECHO_REQUEST = 8,
}

/**
 * Modelo que representa un paquete ICMP.
 */
export interface ICMPPacket extends Packet {
    /* Tipo de mensaje ICMP */
    type: ICMPType | number;
    /* Código de mensaje ICMP */
    code: number;
    /** Identificador de la solicitud */
    identifier: number;
    /** Número de secuencia */
    sequence: number;
}

/**
 * Enum que representa las banderas de control de TCP.
 */
export enum TCPFlags {
    FIN = 1,
    SYN = 2,
    RST = 4,
    PSH = 8,
    ACK = 16,
    URG = 32,
}

/**
 * Modelo que representa un paquete TCP.
 */
export interface TCPPacket extends Packet {
    /* Bandera TCP */
    tcpFlags: TCPFlags | number;
    /* Número de secuencia */
    sequence: number;
    /* Número de acuse de recibo */
    ack: number;
}

/**
 * Modelo que representa un paquete UDP.
 */
export interface UDPPacket extends Packet {}

/**
 * Conjunto de paquetes de red.
 */
export namespace Packet {
    /**
     * Crea un paquete ICMP Echo Request.
     *
     * @param srcIP Dirección IP de origen.
     * @param dstIP Dirección IP de destino.
     * @returns Paquete ICMP Echo Request.
     */
    export const ICMPEchoRequest = (
        srcIP: string,
        dstIP: string,
        payload: string = "Ping request",
    ): ICMPPacket => {
        const headerSize = 8;
        const payloadSize = new TextEncoder().encode(payload).length;

        return {
            srcIP,
            dstIP,
            transportProtocol: TransportProtocol.ICMP,
            payload,
            totalBytes: headerSize + payloadSize,
            headerSize,
            payloadSize,
            timestamp: new Date(),
            ttl: 64,
            type: ICMPType.ECHO_REQUEST,
            code: 0,
            identifier: Math.floor(Math.random() * 65535),
            sequence: Math.floor(Math.random() * 65535),
        };
    };

    /**
     * Crea un paquete ICMP Echo Reply.
     *
     * @returns Paquete ICMP Echo Reply.
     */
    export const ICMPEchoReply = (
        srcIP: string,
        dstIP: string,
        identifier: number,
        sequence: number,
        payload: string = "Pong response",
    ): ICMPPacket => {
        const headerSize = 8;
        const payloadSize = new TextEncoder().encode(payload).length;

        return {
            srcIP,
            dstIP,
            transportProtocol: TransportProtocol.ICMP,
            payload,
            totalBytes: headerSize + payloadSize,
            headerSize,
            payloadSize,
            timestamp: new Date(),
            ttl: 64,
            type: ICMPType.ECHO_REPLY,
            code: 0,
            identifier,
            sequence,
        };
    };

    /**
     * Crea un paquete TCP.
     *
     * @param srcIP Dirección IP de origen.
     * @param dstIP Dirección IP de destino.
     * @param srcPort Puerto de origen.
     * @param dstPort Puerto de destino.
     * @param sequence Número de secuencia.
     * @param ack Número de acuse de recibo.
     * @param tcpFlags Banderas TCP.
     * @param payload Datos del paquete.
     * @returns Paquete TCP.
     */
    export const TCP = (
        srcIP: string,
        dstIP: string,
        srcPort: number,
        dstPort: number,
        sequence: number,
        ack: number,
        tcpFlags: TCPFlags | number,
        payload: string = "",
    ): TCPPacket => {
        const headerSize = 20;
        const payloadSize = new TextEncoder().encode(payload).length;

        return {
            srcIP,
            dstIP,
            srcPort,
            dstPort,
            transportProtocol: TransportProtocol.TCP,
            payload,
            totalBytes: headerSize + payloadSize,
            headerSize,
            payloadSize,
            timestamp: new Date(),
            ttl: 64,
            sequence,
            ack,
            tcpFlags,
        };
    };

    /**
     * Crea un paquete TCP SYN.
     *
     * @param srcIP Dirección IP de origen.
     * @param dstIP Dirección IP de destino.
     * @param srcPort Puerto de origen.
     * @param dstPort Puerto de destino.
     * @returns Paquete TCP SYN.
     */
    export const TCPSYN = (
        srcIP: string,
        dstIP: string,
        srcPort: number,
        dstPort: number,
    ): TCPPacket =>
        TCP(
            srcIP,
            dstIP,
            srcPort,
            dstPort,
            Math.floor(Math.random() * 1000),
            0,
            TCPFlags.SYN,
        );

    /**
     * Crea un paquete TCP SYN-ACK.
     *
     * @param srcIP Dirección IP de origen.
     * @param dstIP Dirección IP de destino.
     * @param srcPort Puerto de origen.
     * @param dstPort Puerto de destino.
     * @param sequence Número de secuencia del paquete SYN.
     * @returns Paquete TCP SYN-ACK.
     **/
    export const TCPSYNACK = (
        srcIP: string,
        dstIP: string,
        srcPort: number,
        dstPort: number,
        sequence: number,
    ): TCPPacket =>
        TCP(
            srcIP,
            dstIP,
            srcPort,
            dstPort,
            Math.floor(Math.random() * 1000),
            sequence + 1,
            TCPFlags.SYN | TCPFlags.ACK,
        );

    /**
     * Crea un paquete TCP ACK.
     *
     * @param srcIP Dirección IP de origen.
     * @param dstIP Dirección IP de destino.
     * @param srcPort Puerto de origen.
     * @param dstPort Puerto de destino.
     * @param sequence Número de secuencia del paquete SYN-ACK.
     * @param ack Número de acuse de recibo del paquete SYN-ACK.
     * @returns Paquete TCP ACK.
     **/
    export const TCPACK = (
        srcIP: string,
        dstIP: string,
        srcPort: number,
        dstPort: number,
        sequence: number,
        ack: number,
    ): TCPPacket =>
        TCP(
            srcIP,
            dstIP,
            srcPort,
            dstPort,
            ack + 1,
            sequence + 1,
            TCPFlags.ACK,
        );

    /**
     * Crea un paquete UDP.
     *
     * @param srcIP Dirección IP de origen.
     * @param dstIP Dirección IP de destino.
     * @param srcPort Puerto de origen.
     * @param dstPort Puerto de destino.
     * @param payload Datos del paquete.
     * @returns Paquete UDP.
     */
    export const UDP = (
        srcIP: string,
        dstIP: string,
        srcPort: number,
        dstPort: number,
        payload: string = "",
    ): UDPPacket => {
        const headerSize = 8;
        const payloadSize = new TextEncoder().encode(payload).length;

        return {
            srcIP,
            dstIP,
            srcPort,
            dstPort,
            transportProtocol: TransportProtocol.UDP,
            payload,
            totalBytes: headerSize + payloadSize,
            headerSize,
            payloadSize,
            timestamp: new Date(),
            ttl: 64,
        };
    };
}
