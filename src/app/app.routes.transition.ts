import {
    animate,
    query,
    style,
    transition,
    trigger,
} from "@angular/animations";

export const floatAnimation = trigger("floatAnimation", [
    transition("_ => *", [
        query(
            ":enter",
            [
                style({
                    transform: "translateX(100%)",
                    opacity: 0,
                }),
                animate(
                    "0.5s ease-in-out",
                    style({
                        transform: "translateX(0)",
                        opacity: 1,
                    }),
                ),
            ],
            { optional: true },
        ),
    ]),
    transition("* => _", [
        query(
            ":leave",
            [
                style({
                    transform: "translateX(0)",
                    opacity: 1,
                }),
                animate(
                    "0.5s ease-in-out",
                    style({
                        transform: "translateX(100%)",
                        opacity: 0,
                    }),
                ),
            ],
            { optional: true },
        ),
    ]),
]);

export const fadeAnimation = trigger("fadeAnimation", [
    transition("_ <=> *", []),
    transition("* => *", [
        query(":enter", [style({ display: "none", opacity: 0 })], {
            optional: true,
        }),
        query(
            ":leave",
            [
                animate("0.25s ease-in-out", style({ opacity: 0 })),
                style({ display: "none" }),
            ],
            { optional: true },
        ),
        query(
            ":enter",
            [
                style({ display: "flex" }),
                animate("0.25s ease-in-out", style({ opacity: 1 })),
            ],
            { optional: true },
        ),
    ]),
]);
