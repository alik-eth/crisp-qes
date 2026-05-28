import { useState } from "react";
import { Masthead } from "./components/Masthead";
import { Footer } from "./components/Footer";
import { Landing } from "./pages/Landing";
import { PetitionList } from "./pages/PetitionList";
import { Sign } from "./pages/Sign";
import { Done } from "./pages/Done";

type View =
    | { kind: "landing" }
    | { kind: "list" }
    | { kind: "sign"; petitionId: bigint }
    | { kind: "done"; petitionId: bigint; txHash: `0x${string}`; newCount: number };

export function App() {
    const [view, setView] = useState<View>({ kind: "landing" });

    return (
        <div className="shell">
            <Masthead onTogglePetitions={() => setView({ kind: "list" })} />
            {view.kind === "landing" ? (
                <Landing onBrowse={() => setView({ kind: "list" })} />
            ) : view.kind === "list" ? (
                <PetitionList onSign={(id) => setView({ kind: "sign", petitionId: id })} />
            ) : view.kind === "sign" ? (
                <Sign
                    petitionId={view.petitionId}
                    onBack={() => setView({ kind: "list" })}
                    onDone={(txHash, newCount) =>
                        setView({
                            kind: "done",
                            petitionId: view.petitionId,
                            txHash,
                            newCount,
                        })
                    }
                />
            ) : (
                <Done
                    petitionId={view.petitionId}
                    txHash={view.txHash}
                    newCount={view.newCount}
                    onReturn={() => setView({ kind: "list" })}
                />
            )}
            <Footer />
        </div>
    );
}
