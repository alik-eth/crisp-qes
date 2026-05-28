import { useState } from "react";
import { Masthead } from "./components/Masthead";
import { Footer } from "./components/Footer";
import { Landing } from "./pages/Landing";
import { Petitions } from "./pages/Petitions";
import { Enroll } from "./pages/Enroll";
import { Sign } from "./pages/Sign";
import { Done } from "./pages/Done";
import { Recover } from "./pages/Recover";

type View =
    | { kind: "landing" }
    | { kind: "list"; nonce?: number }
    | { kind: "enroll" }
    | { kind: "recover" }
    | { kind: "sign"; petitionId: bigint }
    | { kind: "done"; petitionId: bigint; txHash: `0x${string}`; vote: number };

export function App() {
    const [view, setView] = useState<View>({ kind: "landing" });

    return (
        <div className="shell">
            <Masthead
                onTogglePetitions={() => setView({ kind: "list" })}
                onEnroll={() => setView({ kind: "enroll" })}
                onRecover={() => setView({ kind: "recover" })}
            />
            {view.kind === "landing" ? (
                <Landing onBrowse={() => setView({ kind: "list" })} />
            ) : view.kind === "list" ? (
                <Petitions
                    key={view.nonce ?? 0}
                    onSign={(id) => setView({ kind: "sign", petitionId: id })}
                />
            ) : view.kind === "enroll" ? (
                <Enroll
                    onBack={() => setView({ kind: "list" })}
                    onDone={() => setView({ kind: "list", nonce: Date.now() })}
                />
            ) : view.kind === "recover" ? (
                <Recover onBack={() => setView({ kind: "list" })} />
            ) : view.kind === "sign" ? (
                <Sign
                    petitionId={view.petitionId}
                    onBack={() => setView({ kind: "list" })}
                    onDone={(txHash, vote) =>
                        setView({
                            kind: "done",
                            petitionId: view.petitionId,
                            txHash,
                            vote,
                        })
                    }
                />
            ) : (
                <Done
                    petitionId={view.petitionId}
                    txHash={view.txHash}
                    vote={view.vote}
                    onReturn={() => setView({ kind: "list" })}
                />
            )}
            <Footer />
        </div>
    );
}
