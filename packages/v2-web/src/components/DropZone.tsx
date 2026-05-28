import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

interface Props {
    onFile: (file: File) => void;
    accept?: string;
    busy?: boolean;
}

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
            className={`drop ${active ? "drop--active" : ""}`}
            onDragOver={(e) => {
                e.preventDefault();
                setActive(true);
            }}
            onDragLeave={() => setActive(false)}
            onDrop={onDrop}
            onClick={() => inputRef.current?.click()}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
            }}
        >
            <p className="drop__headline">{t("sign.upload.headline")}</p>
            <p className="drop__hint">{t("sign.upload.hint")}</p>
            <button className="btn btn--ghost btn--small" type="button" disabled={busy}>
                {busy ? t("sign.upload.parsing") : t("sign.upload.browse")}
            </button>
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
