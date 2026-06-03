import { useState, useCallback } from "react";
import { Route, Switch, Redirect, useLocation } from "wouter";
import { Masthead } from "./components/Masthead.js";
import { Footer } from "./components/Footer.js";
import { RegisterModal } from "./components/RegisterModal.js";
import { SignInModal } from "./components/SignInModal.js";
import { useAccountState } from "./lib/account.js";
import { Landing } from "./pages/Landing.js";
import { Petitions } from "./pages/Petitions.js";
import { PetitionDetail } from "./pages/PetitionDetail.js";
import { CreatePetition } from "./pages/CreatePetition.js";
import { Recover } from "./pages/Recover.js";
import { Me } from "./pages/Me.js";
import { About } from "./pages/About.js";
import { V3Enroll } from "./pages/V3Enroll.js";
import { Rounds } from "./pages/Rounds.js";
import { NotFound } from "./pages/NotFound.js";

type Modal = null | { kind: "signin" } | { kind: "register" };

export function App() {
    const { state, loading, refresh } = useAccountState();
    const [modal, setModal] = useState<Modal>(null);
    const [, navigate] = useLocation();

    const openSignIn = useCallback(() => {
        if (state.kind === "guest") setModal({ kind: "register" });
        else setModal({ kind: "signin" });
    }, [state.kind]);

    const onChipClick = useCallback(() => {
        navigate("/me");
    }, [navigate]);

    const onRegistered = useCallback(async () => {
        await refresh();
        setModal(null);
        navigate("/verify");
    }, [refresh, navigate]);

    const onUnlocked = useCallback(() => {
        setModal(null);
        if (state.kind === "account") navigate("/verify");
    }, [state.kind, navigate]);

    return (
        <div className="shell">
            <Masthead
                state={state}
                onSignInRequest={openSignIn}
                onChipClick={onChipClick}
            />
            <main className="page" style={{ flex: 1 }}>
                {loading ? null : (
                    <Switch>
                        <Route path="/">
                            <Landing state={state} onSignIn={openSignIn} />
                        </Route>
                        <Route path="/petitions">
                            <Petitions state={state} onSignIn={openSignIn} />
                        </Route>
                        <Route path="/rounds">
                            <Rounds />
                        </Route>
                        <Route path="/p/new">
                            {state.kind !== "verified" ? (
                                <Redirect to="/petitions" />
                            ) : (
                                <CreatePetition />
                            )}
                        </Route>
                        <Route path="/p/:id">
                            {(params) => (
                                <PetitionDetail
                                    id={params.id!}
                                    state={state}
                                    onSignIn={openSignIn}
                                    refresh={refresh}
                                />
                            )}
                        </Route>
                        <Route path="/verify">
                            {state.kind === "guest" ? (
                                <Redirect to="/" />
                            ) : state.kind === "verified" ? (
                                <Redirect to="/petitions" />
                            ) : (
                                <V3Enroll onDone={refresh} />
                            )}
                        </Route>
                        <Route path="/recover">
                            <Recover onDone={refresh} />
                        </Route>
                        <Route path="/me">
                            {state.kind === "guest" ? (
                                <Redirect to="/" />
                            ) : (
                                <Me state={state} refresh={refresh} />
                            )}
                        </Route>
                        <Route path="/about">
                            <About />
                        </Route>
                        <Route path="/v3">
                            <Redirect to="/verify" />
                        </Route>
                        <Route>
                            <NotFound />
                        </Route>
                    </Switch>
                )}
            </main>
            <Footer />
            {modal?.kind === "register" ? (
                <RegisterModal
                    onClose={() => setModal(null)}
                    onRegistered={onRegistered}
                />
            ) : null}
            {modal?.kind === "signin" && state.credentialId ? (
                <SignInModal
                    onClose={() => setModal(null)}
                    credentialId={state.credentialId}
                    onUnlocked={onUnlocked}
                    onRecover={() => {
                        setModal(null);
                        navigate("/recover");
                    }}
                />
            ) : null}
        </div>
    );
}
