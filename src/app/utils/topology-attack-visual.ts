import { AttackExecution, AttackStatus } from "@models/attack-execution";
import { Connection } from "@models/connection";
import { SecurityEvent, SecurityEventType } from "@models/security-event";

/**
 * Derives the attack-line presentation from the existing attack and event state.
 * Terminal lifecycle events end the attack animation for their unique execution
 * ID, even if the engine still retains that execution in its active snapshot.
 */
export function isConnectionUnderActiveAttack(
    connection: Connection,
    attacks: readonly AttackExecution[],
    events: readonly SecurityEvent[],
): boolean {
    const terminalAttackEvents = new Set([
        SecurityEventType.MITIGATION_APPLIED,
        SecurityEventType.ATTACK_COMPLETED,
        SecurityEventType.ATTACK_STOPPED,
        SecurityEventType.ATTACK_FAILED,
        SecurityEventType.RECOVERY_COMPLETED,
    ]);
    const terminalAttackIds = new Set(
        events
            .filter((event) => terminalAttackEvents.has(event.type))
            .map(
                (event) =>
                    event.relatedAttackId ??
                    event.metadata["relatedAttackId"] ??
                    event.metadata["attackId"],
            )
            .filter((id): id is string => typeof id === "string" && id.length > 0),
    );

    return attacks.some(
        (attack) =>
            attack.status === AttackStatus.RUNNING &&
            (attack.config.targetNodeMac === connection.node1.mac ||
                attack.config.targetNodeMac === connection.node2.mac) &&
            !terminalAttackIds.has(attack.id),
    );
}
