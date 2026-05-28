// App-wide wallet session.
//
// PetitionList needs to know whether a wallet is currently connected (to
// decide whether to render the "withdraw deposit" button), and Create
// needs the same session to submit createPetition. Rather than each page
// holding its own state, both read from a small React context.
//
// The wallet itself is module-cached inside `lib/wallet.ts` — this
// context only tracks the user-facing session object so the React tree
// re-renders when it changes.

import {
    createContext,
    useCallback,
    useContext,
    useMemo,
    useState,
    type ReactNode,
} from "react";
import type { WalletSession } from "./wallet";

interface WalletCtx {
    session: WalletSession | null;
    setSession: (s: WalletSession | null) => void;
    clearSession: () => void;
}

const Ctx = createContext<WalletCtx | null>(null);

export function WalletProvider({ children }: { children: ReactNode }) {
    const [session, setSession] = useState<WalletSession | null>(null);
    const clearSession = useCallback(() => setSession(null), []);
    const value = useMemo<WalletCtx>(
        () => ({ session, setSession, clearSession }),
        [session, clearSession],
    );
    return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useWallet(): WalletCtx {
    const v = useContext(Ctx);
    if (!v) throw new Error("useWallet() called outside <WalletProvider>");
    return v;
}
