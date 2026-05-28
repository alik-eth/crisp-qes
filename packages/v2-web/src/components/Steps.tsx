import { useTranslation } from "react-i18next";

export type StepKey =
    | "binding"
    | "upload"
    | "verify"
    | "trust"
    | "nullifier"
    | "prove"
    | "submit";

const ORDER: StepKey[] = [
    "binding",
    "upload",
    "verify",
    "trust",
    "nullifier",
    "prove",
    "submit",
];

interface Props {
    active: StepKey;
    done: Set<StepKey>;
}

export function Steps({ active, done }: Props) {
    const { t } = useTranslation();
    return (
        <ol className="steps">
            {ORDER.map((k) => {
                const isActive = k === active;
                const isDone = done.has(k);
                const cls = [
                    "steps__item",
                    isActive ? "steps__item--active" : "",
                    isDone && !isActive ? "steps__item--done" : "",
                ]
                    .filter(Boolean)
                    .join(" ");
                return (
                    <li key={k} className={cls}>
                        {t(`sign.steps.${k}`)}
                    </li>
                );
            })}
        </ol>
    );
}
