import { Command, FlowGenerator } from "@models/flow-generator";
import { Packet } from "@models/packet";
import { paramsCount } from "@utils/parse_script";
import { randomInt } from "@utils/random";

/**
 * Ataque que se puede realizar.
 */
export interface Attack extends Command {}

/**
 * Ataques que se pueden realizar.
 */
export type Attacks = Attack[];

/**
 * Atacante Phantom.
 */
export class PhantomAttacker extends FlowGenerator {
    /** Ataques internos que se pueden realizar */
    public readonly internalAttacks: Attacks = [
        {
            id: "dos",
            name: "Denial of Service (DoS)",
            multiple: false,
        },
        {
            id: "mqtt_flood",
            name: "MQTT Flood",
            multiple: false,
        },
        {
            id: "sensor_spoof",
            name: "Sensor Spoof",
            multiple: false,
        },
        {
            id: "brute_force",
            name: "Brute Force",
            multiple: false,
        },
        {
            id: "port_scan",
            name: "Port Scan",
            multiple: false,
        },
    ];
    /** Ataques externos que se pueden realizar */
    private _externalAttacks: Attacks = [];
    /** Ataques externos que se pueden realizar */
    public get externalAttacks(): Attacks {
        return [...this._externalAttacks];
    }

    /**
     * Realiza un ataque de denegación de servicio (DoS) a una dirección IP.
     *
     * @param dstIP Dirección IP de destino.
     * @param dstPort Puerto de destino.
     * @param ttlRange Rango de TTL.
     * @param packetNum Número de paquetes a enviar.
     */
    public dos(
        dstIP: string,
        dstPort: number,
        ttlRange: [number, number],
        packetNum: number,
    ): void {
        for (let i = 0; i < packetNum; i++) {
            const packet = Packet.TCPSYN(
                this.node.ip!,
                dstIP,
                randomInt(1024, 65535),
                dstPort,
            );

            packet.ttl = randomInt(ttlRange[0], ttlRange[1]);
            this.node.sendPacket(packet);
        }
    }

    public override loadLibrary(library: any | undefined): void {
        if (!library) {
            super.loadLibrary(library);
            this._externalAttacks = [];
            return;
        }

        const attacks = Object.keys(library).filter((e) =>
            e.startsWith("atk_"),
        );

        super.loadLibrary(library);
        this._externalAttacks = [];
        for (const atk of attacks) {
            this.library![atk] = (...args) =>
                library[atk](
                    {
                        mac: this.node.mac,
                        ip: this.node.ip,
                        name: this.node.name,
                        type: this.node.type as string,
                        send: (packet: Packet) => this.node.sendPacket(packet),
                    },
                    ...args,
                );
            this._externalAttacks.push({
                id: atk,
                name: atk.substring(4).replaceAll("_", " "),
                multiple: paramsCount(library[atk]) === Infinity,
            });
        }
    }

    /**
     * Ejecuta un ataque de una biblioteca.
     *
     * @param fn Nombre de la función a ejecutar.
     * @param args Argumentos de la función.
     */
    public attack(fn: string, ...args: any[]): void {
        this.execute(fn, ...args);
    }
}
