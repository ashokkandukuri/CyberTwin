import { Inject, Injectable, Signal } from "@angular/core";
import { toSignal } from "@angular/core/rxjs-interop";
import { NavigationEnd, Router as NavigationRouter } from "@angular/router";
import { Device } from "@models/device";
import { Network } from "@models/network";
import { Node, NodeType } from "@models/node";
import { Position } from "@models/position";
import { Router } from "@models/router";
import {
    AddNodeDialogComponent,
    AddNodeDialogContext,
} from "@routes/dialogs/add-node-dialog.component";
import {
    DeleteNodeDialogComponent,
    DeleteNodeDialogContext,
} from "@routes/dialogs/delete-node-dialog.component";
import { ConfigService } from "@services/config.service";
import { SecurityEventService } from "@services/security-event.service";
import { StateService } from "@services/state.service";
import { Subject } from "rxjs";
import { HlmDialogService } from "@spartan-ng/helm/dialog";
import { dump, load } from "js-yaml";
import { toast } from "ngx-sonner";
import { filter, map } from "rxjs";
import { LibraryService } from "./library.service";
import { ModelsService } from "./models.service";

/**
 * Clase que permite gestionar la red de dispositivos.
 */
@Injectable({ providedIn: "root" })
export class NetworkService {
    /** Red de dispositivos */
    private readonly _network: Network = new Network();
    /** Obtiene los nodos de la red de dispositivos */
    public get nodes(): Node[] {
        return this._network.nodes;
    }
    /** Obtiene el router de la red de dispositivos */
    public get router(): Router | undefined {
        return this._network.router;
    }
    /** Obtiene los dispositivos de la red de dispositivos */
    public get devices(): Device[] | undefined {
        return this._network.devices;
    }
    /** Dirección MAC del nodo seleccionado */
    public readonly focusedNode: Signal<Node | undefined>;

    public readonly onNetworkReset = new Subject<void>();
    public readonly onNodeAdded = new Subject<Node>();
    public readonly onNodeRemoved = new Subject<string>();

    /**
     * Constructor del servicio de gestión de la red de dispositivos.
     *
     * @param navigationRouter Servicio de navegación de la aplicación
     * @param dialog Servicio de diálogos de la aplicación
     * @param config Servicio de configuración de la aplicación
     * @param state Servicio de estado de la aplicación
     */
    public constructor(
        public readonly navigationRouter: NavigationRouter,
        @Inject(HlmDialogService) public readonly dialog: HlmDialogService,
        public readonly config: ConfigService,
        public readonly state: StateService,
        public readonly securityEvents: SecurityEventService,
        _: ModelsService,
        __: LibraryService,
    ) {
        // Obtener el nodo seleccionado
        this.focusedNode = toSignal(
            this.navigationRouter.events.pipe(
                filter((event) => event instanceof NavigationEnd),
                map(({ url }) =>
                    url.split("/").length > 1 ? url.split("/")[1] : undefined,
                ),
                map((mac) => this._network.getNode(mac ?? "")),
            ),
        );
    }

    /**
     * Crea una nueva red de dispositivos.
     */
    public new(): void {
        this._network.reset();
        // Notify simulation services first so active attack timers and other
        // network-scoped state can be stopped before event history is cleared.
        this.onNetworkReset.next();
        // Reset Security Event state after subscribers have performed cleanup.
        this.securityEvents.reset();
        // Comprobar si hay un nodo seleccionado
        if (this.focusedNode()) this.navigationRouter.navigate([""]);
        // Guardar el estado de la red de dispositivos
        this.state.reset(false);
        toast.success(this.config.translate.instant("PROJECT_CREATED"));
    }

    /**
     * Carga una red de dispositivos desde un archivo.
     */
    public loadFromFile(): void {
        toast.promise(ConfigService.openFile(".yaml"), {
            loading: this.config.translate.instant("PROJECT_IMPORTING"),
            success: (data: string) => {
                try {
                    this._network.fromObject(load(data));
                } catch (error) {
                    this._network.reset();
                    this.onNetworkReset.next();
                    this.securityEvents.reset();
                    this.state.reset(false);
                    throw error;
                }

                // Sync event will be handled by DigitalTwinService
                this.onNetworkReset.next();
                this.securityEvents.reset();

                // Comprobar si hay un nodo seleccionado
                if (
                    this.focusedNode() &&
                    !this._network.getNode(this.focusedNode()!.mac ?? "")
                )
                    this.navigationRouter.navigate([""]);
                // Guardar el estado de la red de dispositivos
                this.state.reset(false);
                this.state.setState(this._network.toObject(), false);
                return this.config.translate.instant("PROJECT_IMPORTED");
            },
            error: () => this.config.translate.instant("PROJECT_NOT_IMPORTED"),
        });
    }

    /**
     * Guarda la red de dispositivos en un archivo.
     */
    public saveToFile(): void {
        toast.promise(
            new Promise<[string, string, string]>((resolve, reject) => {
                const name: string = [
                    "iot",
                    "simulator",
                    ...new Date().toISOString().split(/T|\./g, 2),
                ]
                    .join("_")
                    .replace(/-|:/g, "")
                    .concat(".yaml");
                const content: string = dump(this._network.toObject(), {
                    noCompatMode: true,
                    forceQuotes: true,
                });
                const type: string = "application/x-yaml";

                resolve([name, content, type]);
            }).then(([name, content, type]) =>
                ConfigService.saveFile(name, content, type),
            ),
            {
                loading: this.config.translate.instant("PROJECT_EXPORTING"),
                success: () => {
                    // Guardar el estado de la red de dispositivos
                    this.state.replaceState(this._network.toObject(), false);
                    return this.config.translate.instant("PROJECT_EXPORTED");
                },
                error: () =>
                    this.config.translate.instant("PROJECT_NOT_EXPORTED"),
            },
        );
    }

    /**
     * Añade un nodo a la red de dispositivos.
     *
     * @param type Tipo de nodo
     * @param position Posición del nodo
     */
    public addNode(
        type?: NodeType | readonly NodeType[] | NodeType[],
        position?: Position,
    ): Promise<boolean> {
        return new Promise((resolve, reject) => {
            if (
                this._network.router &&
                (Array.isArray(type)
                    ? NodeType.RouterTypes.some((t) => type.includes(t))
                    : NodeType.RouterTypes.includes(type as NodeType))
            ) {
                toast.error(this.config.translate.instant("ROUTER_EXISTS"));
                return reject();
            }

            this.dialog
                .open(AddNodeDialogComponent, { context: { type } })
                .closed$.subscribe((context: AddNodeDialogContext) => {
                    if (!context) return resolve(false);

                    const newNode = this._network.addNode(
                        NodeType.RouterTypes.includes(context.type)
                            ? new Router(context.name, position)
                            : new Device(
                                  context.name,
                                  context.type as any,
                                  position,
                              ),
                    );
                    // Create Digital Twin for the new node
                    this.onNodeAdded.next(newNode);
                    // Guardar el estado de la red de dispositivos
                    this.state.setState(this._network.toObject(), false);
                    toast.success(
                        this.config.translate.instant("NODE_ADDED", {
                            name: context.name,
                        }),
                    );
                    return resolve(true);
                });
        });
    }

    /**
     * Elimina un nodo de la red de dispositivos.
     *
     * @param mac Dirección MAC del nodo
     */
    public deleteNode(mac: string): Promise<boolean> {
        return new Promise((resolve, reject) => {
            const node = this._network.getNode(mac);

            if (!node) {
                toast.error(
                    this.config.translate.instant("NODE_NOT_FOUND", {
                        name: mac,
                    }),
                );
                return reject();
            }

            this.dialog
                .open(DeleteNodeDialogComponent, {
                    context: { node },
                })
                .closed$.subscribe((context: DeleteNodeDialogContext) => {
                    if (!context) return resolve(false);

                    this._network.deleteNode(context.node.mac);
                    // Remove Digital Twin for the deleted node
                    this.onNodeRemoved.next(context.node.mac);
                    // Comprobar si el nodo eliminado es el nodo seleccionado
                    if (this.focusedNode()?.mac === node.mac)
                        this.navigationRouter.navigate([""]);
                    // Guardar el estado de la red de dispositivos
                    this.state.setState(this._network.toObject(), false);
                    toast.success(
                        this.config.translate.instant("NODE_DELETED", {
                            name: context.node.name,
                        }),
                    );
                    return resolve(true);
                });
        });
    }

    /**
     * Obtiene un nodo de la red de dispositivos.
     *
     * @param mac Dirección MAC del nodo
     * @returns Nodo obtenido
     */
    public getNode(mac: string): Node | undefined {
        return this._network.getNode(mac);
    }

    /**
     * Obtiene los nodos conectados a un nodo de la red de dispositivos.
     *
     * @param mac Dirección MAC del nodo
     * @returns Nodos conectados
     */
    public getConnectedNodes(mac?: string): Node[] {
        return this._network.getConnectedNodes(mac);
    }
}
