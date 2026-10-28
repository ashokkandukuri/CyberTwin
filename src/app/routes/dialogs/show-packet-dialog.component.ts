import { CommonModule } from "@angular/common";
import { Component, inject } from "@angular/core";
import { TranslateModule } from "@ngx-translate/core";
import { ConfigService } from "@services/config.service";
import { BrnDialogRef, injectBrnDialogContext } from "@spartan-ng/brain/dialog";
import { BrnSelectImports } from "@spartan-ng/brain/select";
import { BrnTooltipImports } from "@spartan-ng/brain/tooltip";
import { HlmDialogImports } from "@spartan-ng/helm/dialog";
import { HlmSelectImports } from "@spartan-ng/helm/select";
import { HlmTooltipImports } from "@spartan-ng/helm/tooltip";

export interface ShowPacketDialogContext {
    packet: any;
}

@Component({
    selector: "app-show-packet-dialog",
    imports: [
        CommonModule,
        TranslateModule,
        BrnSelectImports,
        HlmTooltipImports,
        BrnTooltipImports,
        HlmDialogImports,
        HlmSelectImports,
    ],
    template: `
        <hlm-dialog-header class="px-6">
            <h3 hlmDialogTitle>{{ "PACKET_DETAILS" | translate }}</h3>
        </hlm-dialog-header>
        <div class="grid gap-4 overflow-y-auto px-6 pb-6">
            <div class="grid grid-cols-4 items-center gap-4">
                <label
                    hlmLabel
                    class="text-muted-foreground items-center text-right text-sm font-medium"
                    >{{ "PACKET_SRC_IP" | translate }}</label
                >
                <span class="col-span-3 overflow-hidden text-ellipsis">{{
                    context.packet.srcIP
                }}</span>
            </div>
            <div class="grid grid-cols-4 items-center gap-4">
                <label
                    hlmLabel
                    class="text-muted-foreground items-center text-right text-sm font-medium"
                    >{{ "PACKET_DST_IP" | translate }}</label
                >
                <span class="col-span-3 overflow-hidden text-ellipsis">{{
                    context.packet.dstIP
                }}</span>
            </div>
            <div class="grid grid-cols-4 items-center gap-4">
                <label
                    hlmLabel
                    class="text-muted-foreground items-center text-right text-sm font-medium"
                    >{{ "PACKET_SRC_PORT" | translate }}</label
                >
                <span class="col-span-3 overflow-hidden text-ellipsis">{{
                    context.packet.srcPort
                }}</span>
            </div>
            <div class="grid grid-cols-4 items-center gap-4">
                <label
                    hlmLabel
                    class="text-muted-foreground items-center text-right text-sm font-medium"
                    >{{ "PACKET_DST_PORT" | translate }}</label
                >
                <span class="col-span-3 overflow-hidden text-ellipsis">{{
                    context.packet.dstPort
                }}</span>
            </div>
            <div class="grid grid-cols-4 items-center gap-4">
                <label
                    hlmLabel
                    class="text-muted-foreground items-center text-right text-sm font-medium"
                    >{{ "PACKET_TRANSPORT_PROTOCOL" | translate }}</label
                >
                <span class="col-span-3 overflow-hidden text-ellipsis">{{
                    context.packet.transportProtocol
                }}</span>
            </div>
            <div class="grid grid-cols-4 items-center gap-4">
                <label
                    hlmLabel
                    class="text-muted-foreground items-center text-right text-sm font-medium"
                    >{{ "PACKET_APPLICATION_PROTOCOL" | translate }}</label
                >
                <span class="col-span-3 overflow-hidden text-ellipsis">{{
                    context.packet.applicationProtocol
                }}</span>
            </div>
            <div class="grid grid-cols-4 items-center gap-4">
                <label
                    hlmLabel
                    class="text-muted-foreground items-center text-right text-sm font-medium"
                    >{{ "PACKET_PAYLOAD" | translate }}</label
                >
                <hlm-tooltip>
                    <span
                        hlmTooltipTrigger
                        showDelay="500"
                        class="col-span-3 inline-block truncate">
                        {{ context.packet.payload }}
                    </span>
                    <span
                        *brnTooltipContent
                        class="overflow-hidden wrap-break-word break-all whitespace-normal">
                        {{ context.packet.payload }}
                    </span>
                </hlm-tooltip>
            </div>
            <div class="grid grid-cols-4 items-center gap-4">
                <label
                    hlmLabel
                    class="text-muted-foreground items-center text-right text-sm font-medium"
                    >{{ "PACKET_TOTAL_BYTES" | translate }}</label
                >
                <span class="col-span-3 overflow-hidden text-ellipsis">{{
                    context.packet.totalBytes
                }}</span>
            </div>
            <div class="grid grid-cols-4 items-center gap-4">
                <label
                    hlmLabel
                    class="text-muted-foreground items-center text-right text-sm font-medium"
                    >{{ "PACKET_HEADER_SIZE" | translate }}</label
                >
                <span class="col-span-3 overflow-hidden text-ellipsis">{{
                    context.packet.headerSize
                }}</span>
            </div>
            <div class="grid grid-cols-4 items-center gap-4">
                <label
                    hlmLabel
                    class="text-muted-foreground items-center text-right text-sm font-medium"
                    >{{ "PACKET_PAYLOAD_SIZE" | translate }}</label
                >
                <span class="col-span-3 overflow-hidden text-ellipsis">{{
                    context.packet.payloadSize
                }}</span>
            </div>
            <div class="grid grid-cols-4 items-center gap-4">
                <label
                    hlmLabel
                    class="text-muted-foreground items-center text-right text-sm font-medium"
                    >{{ "PACKET_TIMESTAMP" | translate }}</label
                >
                <span class="col-span-3 overflow-hidden text-ellipsis">{{
                    context.packet.timestamp
                        | date: "medium" : undefined : config.language()
                }}</span>
            </div>
            <div class="grid grid-cols-4 items-center gap-4">
                <label
                    hlmLabel
                    class="text-muted-foreground items-center text-right text-sm font-medium"
                    >{{ "PACKET_TTL" | translate }}</label
                >
                <span class="col-span-3 overflow-hidden text-ellipsis">{{
                    context.packet.ttl
                }}</span>
            </div>
            @if (context.packet.type) {
                <div class="grid grid-cols-4 items-center gap-4">
                    <label
                        hlmLabel
                        class="text-muted-foreground items-center text-right text-sm font-medium"
                        >{{ "PACKET_TYPE" | translate }}</label
                    >
                    <span class="col-span-3 overflow-hidden text-ellipsis">{{
                        context.packet.type
                    }}</span>
                </div>
            }
            @if (context.packet.code) {
                <div class="grid grid-cols-4 items-center gap-4">
                    <label
                        hlmLabel
                        class="text-muted-foreground items-center text-right text-sm font-medium"
                        >{{ "PACKET_CODE" | translate }}</label
                    >
                    <span class="col-span-3 overflow-hidden text-ellipsis">{{
                        context.packet.code
                    }}</span>
                </div>
            }
            @if (context.packet.identifier) {
                <div class="grid grid-cols-4 items-center gap-4">
                    <label
                        hlmLabel
                        class="text-muted-foreground items-center text-right text-sm font-medium"
                        >{{ "PACKET_IDENTIFIER" | translate }}</label
                    >
                    <span class="col-span-3 overflow-hidden text-ellipsis">{{
                        context.packet.identifier
                    }}</span>
                </div>
            }
            @if (context.packet.sequence) {
                <div class="grid grid-cols-4 items-center gap-4">
                    <label
                        hlmLabel
                        class="text-muted-foreground items-center text-right text-sm font-medium"
                        >{{ "PACKET_SEQUENCE" | translate }}</label
                    >
                    <span class="col-span-3 overflow-hidden text-ellipsis">{{
                        context.packet.sequence
                    }}</span>
                </div>
            }
            @if (context.packet.tcpFlags) {
                <div class="grid grid-cols-4 items-center gap-4">
                    <label
                        hlmLabel
                        class="text-muted-foreground items-center text-right text-sm font-medium"
                        >{{ "PACKET_TCP_FLAGS" | translate }}</label
                    >
                    <span class="col-span-3 overflow-hidden text-ellipsis">{{
                        context.packet.tcpFlags
                    }}</span>
                </div>
            }
            @if (context.packet.ack) {
                <div class="grid grid-cols-4 items-center gap-4">
                    <label
                        hlmLabel
                        class="text-muted-foreground items-center text-right text-sm font-medium"
                        >{{ "PACKET_ACK" | translate }}</label
                    >
                    <span class="col-span-3 overflow-hidden text-ellipsis">{{
                        context.packet.ack
                    }}</span>
                </div>
            }
        </div>
    `,
    host: { class: "min-w-96 max-h-[80vh] flex flex-col gap-4" },
})
export class ShowPacketDialogComponent {
    public readonly config = inject(ConfigService);
    protected readonly ref: BrnDialogRef<ShowPacketDialogComponent> = inject(
        BrnDialogRef<ShowPacketDialogComponent>,
    );
    protected readonly context =
        injectBrnDialogContext<ShowPacketDialogContext>();

    public ngOnInit(): void {}
}
