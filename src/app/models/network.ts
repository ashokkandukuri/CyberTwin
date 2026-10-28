import { Connection } from "@models/connection";
import { Device } from "@models/device";
import { Node, NodeType } from "@models/node";
import { Router } from "@models/router";
import { StateService } from "@services/state.service";

/**
 * Clase que representa una red de dispositivos.
 */
@StateService.UseState
export class Network {
    /** Nodos de la red */
    private readonly _nodes: Map<string, Node> = new Map<string, Node>();
    /** Obtiene los nodos de la red */
    public get nodes(): Node[] {
        return [...this._nodes.values()];
    }
    /** Router de la red */
    private _router?: Router;
    /** Obtiene el router de la red */
    public get router(): Router | undefined {
        return this._router;
    }
    /** Obtiene los dispositivos de la red */
    public get devices(): Device[] | undefined {
        const devices = this.nodes.filter(
            ({ type }) => !NodeType.RouterTypes.includes(type),
        ) as Device[];

        return devices.length > 0 ? devices : undefined;
    }

    /**
     * Restablece la red de dispositivos.
     */
    public reset() {
        this._nodes.clear();
        this._router = undefined;
    }

    /**
     * Añade un nodo a la red de dispositivos.
     *
     * @param node Nodo a añadir
     */
    public addNode(node: Node): Node {
        if (this._router && NodeType.RouterTypes.includes(node.type))
            throw new Error("Cannot add more than one router to the network");

        if (NodeType.RouterTypes.includes(node.type))
            this._router = node as Router;
        this._nodes.set(node.mac, node);
        return node;
    }

    /**
     * Elimina un nodo de la red de dispositivos.
     *
     * @param mac Dirección MAC del nodo
     * @returns Indica si el nodo ha sido eliminado
     */
    public deleteNode(mac: string): boolean {
        const node = this._nodes.get(mac);

        if (!node)
            throw new Error(
                "Does not exist a node with the specified MAC address",
            );

        if (NodeType.RouterTypes.includes(node.type)) {
            this._router = undefined;
            (node as Router).removeAllConnections();
        } else if (this._router) (node as Device).disconnect(this._router);
        this._nodes.delete(node.mac);
        return true;
    }

    /**
     * Obtiene un nodo de la red de dispositivos.
     *
     * @param mac Dirección MAC del nodo
     * @returns Nodo obtenido
     */
    public getNode(mac: string): Node | undefined {
        return this._nodes.get(mac);
    }

    /**
     * Obtiene los nodos conectados a un nodo de la red de dispositivos.
     *
     * @param mac Dirección MAC del nodo para obtener los nodos conectados a este.
     * @returns Nodos conectados
     */
    public getConnectedNodes(mac?: string): Node[] {
        return this.nodes.filter((node) => node.ip && mac !== node.mac);
    }

    /**
     * Transforma la red de dispositivos en un objeto.
     *
     * @returns Objeto de la red de dispositivos
     */
    public toObject(): any {
        return {
            exportedAt: new Date().toISOString(),
            router: this.router?.toObject(),
            devices: this.devices?.map((e) => e.toObject()),
        };
    }

    /**
     * Carga una red de dispositivos desde un objeto.
     *
     * @param object Objeto de la red de dispositivos
     */
    public fromObject(object: any): void {
        this.reset();
        // Add the router
        if (object.router) this.addNode(Router.fromObject(object.router));
        // Add the devices
        if (object.devices) {
            object.devices.forEach((obj: any) => {
                const device = this.addNode(Device.fromObject(obj)) as Device;

                if (obj.connection) {
                    device.connect(
                        this.router!,
                        Connection.fromObject(
                            this.router!,
                            device,
                            obj.connection,
                        ),
                    );
                }
            });
        }
    }
}
