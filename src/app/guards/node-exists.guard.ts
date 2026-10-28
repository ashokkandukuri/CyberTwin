import { inject } from "@angular/core";
import {
    ActivatedRouteSnapshot,
    CanActivateFn,
    GuardResult,
    RouterStateSnapshot,
} from "@angular/router";
import { NetworkService } from "@services/network.service";

/**
 * Protector que verifica si un nodo existe en la red.
 *
 * @param route La ruta activada.
 * @param state El estado del router.
 * @returns `true` si el nodo existe, `false` en caso contrario.
 */
export const nodeExistsGuard: CanActivateFn = (
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot,
): GuardResult => {
    const network = inject(NetworkService);
    const { mac } = route.params;

    return network.getNode(mac) ? true : false;
};
