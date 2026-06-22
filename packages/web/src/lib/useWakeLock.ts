// Keep the screen awake during a long on-device task (the ~40s enrollment
// proof). Best-effort: on browsers without the Screen Wake Lock API this is a
// no-op. The OS auto-releases the sentinel when the tab is hidden, so we
// re-acquire on `visibilitychange` whenever the lock is still wanted.
import { useEffect, useRef } from "react";

// Minimal types — the Screen Wake Lock API isn't in every TS lib.dom yet.
interface WakeLockSentinelLike {
    released: boolean;
    release: () => Promise<void>;
    addEventListener: (type: "release", cb: () => void) => void;
}
interface WakeLockLike {
    request: (type: "screen") => Promise<WakeLockSentinelLike>;
}

function getWakeLock(): WakeLockLike | null {
    const wl = (navigator as Navigator & { wakeLock?: WakeLockLike }).wakeLock;
    return wl ?? null;
}

/**
 * Holds a screen wake lock while `active` is true. Releases it when `active`
 * goes false or the component unmounts, and re-acquires it if the tab becomes
 * visible again while still active. Safe to call when unsupported.
 */
export function useWakeLock(active: boolean): void {
    const sentinelRef = useRef<WakeLockSentinelLike | null>(null);

    useEffect(() => {
        if (!active) return;
        const wl = getWakeLock();
        if (!wl) return; // unsupported — silent no-op

        let cancelled = false;

        const acquire = async (): Promise<void> => {
            if (cancelled || sentinelRef.current) return;
            try {
                const s = await wl.request("screen");
                if (cancelled) {
                    void s.release().catch(() => {});
                    return;
                }
                sentinelRef.current = s;
                // The OS may release it on its own (e.g. tab hidden); clear our ref.
                s.addEventListener("release", () => {
                    sentinelRef.current = null;
                });
            } catch {
                // user gesture missing / policy / unsupported — ignore.
            }
        };

        const release = (): void => {
            const s = sentinelRef.current;
            sentinelRef.current = null;
            if (s && !s.released) void s.release().catch(() => {});
        };

        const onVisibility = (): void => {
            if (document.visibilityState === "visible") void acquire();
        };

        void acquire();
        document.addEventListener("visibilitychange", onVisibility);

        return () => {
            cancelled = true;
            document.removeEventListener("visibilitychange", onVisibility);
            release();
        };
    }, [active]);
}
