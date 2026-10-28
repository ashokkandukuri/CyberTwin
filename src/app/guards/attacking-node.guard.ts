import { inject } from "@angular/core";
import {
    ActivatedRouteSnapshot,
    CanActivateFn,
    GuardResult,
    RedirectCommand,
    Router,
    RouterStateSnapshot,
} from "@angular/router";
import { NodeType } from "@models/node";
import { NetworkService } from "@services/network.service";

/**
 * Protector que verifica si un nodo es de tipo "atacante".
 *
 * @param route La ruta activada.
 * @param state El estado del router.
 * @returns `true` si el nodo es un atacante, `false` en caso contrario.
 */
export const attackingNodeGuard: CanActivateFn = (
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot,
): GuardResult => {
    const router = inject(Router);
    const network = inject(NetworkService);
    const { mac } = route.parent!.params;
    const node = network.getNode(mac)!;

    return NodeType.AttackerTypes.includes(node.type)
        ? true
        : new RedirectCommand(router.parseUrl(`/${mac}/network-traffic`));
};
