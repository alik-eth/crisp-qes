import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

interface Props {
    onFile: (file: File) => void;
    accept?: string;
    busy?: boolean;
}

// The whole zone is the affordance: click anywhere on the dashed area
// (or drop a file). The earlier "Обрати файл" inner button was redundant
// and double-fired the input click via event bubbling — see R3-4 in
// benchmarker's round-2 report. Busy state now surfaces as a hint-line
// swap rather than a button label.
export function DropZone({ onFile, accept = ".p7s", busy }: Props) {
    const { t } = useTranslation();
    const [active, setActive] = useState(false);
    const inputRef = useRef<HTMLInputElement>(null);

    const onDrop = useCallback(
        (ev: React.DragEvent<HTMLDivElement>) => {
            ev.preventDefault();
            setActive(false);
            const file = ev.dataTransfer.files?.[0];
            if (file) onFile(file);
        },
        [onFile],
    );

    return (
        <div
            className={`drop ${active ? "drop--active" : ""} ${busy ? "drop--busy" : ""}`}
            onDragOver={(e) => {
                e.preventDefault();
                setActive(true);
            }}
            onDragLeave={() => setActive(false)}
            onDrop={onDrop}
            onClick={() => {
                if (!busy) inputRef.current?.click();
            }}
            role="button"
            tabIndex={0}
            aria-busy={busy ? true : undefined}
            onKeyDown={(e) => {
                if (busy) return;
                if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
            }}
        >
            <p className="drop__headline">{t("enroll.upload.headline")}</p>
            <p className="drop__hint">
                {busy ? t("enroll.upload.parsing") : t("enroll.upload.hint")}
            </p>
            <input
                ref={inputRef}
                type="file"
                accept={accept}
                onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) onFile(f);
                    e.target.value = "";
                }}
            />
        </div>
    );
}
