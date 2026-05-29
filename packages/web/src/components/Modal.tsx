import { useEffect, type ReactNode } from "react";

interface Props {
    title: string;
    onClose: () => void;
    children: ReactNode;
    dismissable?: boolean;
}

export function Modal({ title, onClose, children, dismissable = true }: Props) {
    useEffect(() => {
        if (!dismissable) return;
        const onKey = (e: KeyboardEvent) => {
            if (e.key === "Escape") onClose();
        };
        document.addEventListener("keydown", onKey);
        document.body.style.overflow = "hidden";
        return () => {
            document.removeEventListener("keydown", onKey);
            document.body.style.overflow = "";
        };
    }, [onClose, dismissable]);

    return (
        <div
            className="modal__overlay"
            role="dialog"
            aria-modal="true"
            aria-label={title}
            onClick={dismissable ? onClose : undefined}
        >
            <div className="modal" onClick={(e) => e.stopPropagation()}>
                <div className="modal__head">
                    <h2 className="modal__title">{title}</h2>
                    {dismissable ? (
                        <button
                            type="button"
                            className="modal__close"
                            onClick={onClose}
                            aria-label="Close"
                        >
                            ×
                        </button>
                    ) : null}
                </div>
                <div className="modal__body">{children}</div>
            </div>
        </div>
    );
}
