// 5-step enrollment flow.
//
// 1. Upload .p7s, extract RNOKPP (subjectSerial after `TINUA-`).
// 2. Create a Passkey + read PRF output.
// 3. Blind RNOKPP, call OPRF /blind-eval, verify DLEQ, unblind to obtain `N`.
//    Pedersen-commit `N` to obtain `commitment`. Pedersen-derive `s`.
// 4. Call OPRF /register with the commitment to get Merkle path + attesterSig.
//    Submit `EnrollmentRegistry.updateRoot(newRoot, attesterSig)` via wallet.
// 5. Store the encrypted payload in IndexedDB, show the BIP-39 mnemonic.

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { parseP7s, type ParsedP7s } from "@crisp-qes/sdk";
import { DropZone } from "../components/DropZone";
import { rnokppBytes, tinuaPrefixOk } from "../lib/rnokpp";
import {
    probeWebauthn,
    registerPasskey,
} from "../lib/webauthnPrf";
import { blind, unblind, verifyBlindEval } from "../lib/voprf";
import { pedersenS } from "../lib/pedersen";
import { oprfBlindEval, oprfRegister } from "../lib/oprfClient";
import {
    putEnrollment,
    wrapPayload,
    type EnrollmentPayload,
} from "../lib/encryptedStore";
import { mnemonicFromN } from "../lib/bip39Recovery";
import { BaseError, ContractFunctionRevertedError } from "viem";
import {
    connectInjected,
    connectWalletConnect,
    ensureChain,
    listInjectedProviders,
    startInjectedDiscovery,
    type InjectedDetail,
} from "../lib/wallet";
import { useWallet } from "../lib/walletContext";
import { enrollmentRegistryAbi } from "../lib/abi";
import { config } from "../config";

interface Props {
    onBack: () => void;
    onDone: () => void;
}

type Stage =
    | "upload"
    | "passkey"
    | "oprf"
    | "register"
    | "backup"
    | "done";

function hexEncode(b: Uint8Array): `0x${string}` {
    let s = "0x";
    for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
    return s as `0x${string}`;
}

function hexDecode(h: `0x${string}`): Uint8Array {
    const s = h.slice(2);
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
    }
    return out;
}

export function Enroll({ onBack, onDone }: Props) {
    const { t } = useTranslation();
    const probe = useMemo(() => probeWebauthn(), []);

    const [p7sBytes, setP7sBytes] = useState<Uint8Array | null>(null);
    const [parsed, setParsed] = useState<ParsedP7s | null>(null);
    const [parseErr, setParseErr] = useState<string | null>(null);

    const [passkey, setPasskey] = useState<{
        credentialId: Uint8Array;
        prfOutput: Uint8Array;
    } | null>(null);
    const [passkeyBusy, setPasskeyBusy] = useState(false);
    const [passkeyErr, setPasskeyErr] = useState<string | null>(null);

    const [oprfResult, setOprfResult] = useState<{
        N: Uint8Array;
        blindedElement: Uint8Array;
        s: `0x${string}`;
    } | null>(null);
    const [oprfBusy, setOprfBusy] = useState(false);
    const [oprfErr, setOprfErr] = useState<string | null>(null);

    const [registerResult, setRegisterResult] = useState<{
        merklePath: `0x${string}`[];
        merklePathIndices: (0 | 1)[];
        leafIndex: number;
        newRoot: `0x${string}`;
        newCommitments: `0x${string}`[];
        attesterSig: `0x${string}`;
    } | null>(null);
    const [registerBusy, setRegisterBusy] = useState(false);
    const [registerErr, setRegisterErr] = useState<string | null>(null);

    // On-chain step (user-signed via WalletConnect).
    const { session, setSession, clearSession } = useWallet();
    const [injected, setInjected] = useState<InjectedDetail[]>([]);
    const [chainBusy, setChainBusy] = useState<
        "idle" | "connecting" | "switching" | "submitting" | "mining"
    >("idle");
    const [chainErr, setChainErr] = useState<string | null>(null);
    const [chainTx, setChainTx] = useState<`0x${string}` | null>(null);

    const [mnemonic, setMnemonic] = useState<string | null>(null);
    const [mnemonicRevealed, setMnemonicRevealed] = useState(false);

    const [stage, setStage] = useState<Stage>("upload");

    // Auto-advance the visible "current step" based on which artifacts exist.
    useEffect(() => {
        if (mnemonic) setStage("backup");
        else if (chainTx) setStage("backup");
        else if (registerResult) setStage("register");
        else if (oprfResult) setStage("register");
        else if (passkey) setStage("oprf");
        else if (parsed) setStage("passkey");
        else setStage("upload");
    }, [parsed, passkey, oprfResult, registerResult, chainTx, mnemonic]);

    useEffect(() => {
        startInjectedDiscovery();
        setInjected(listInjectedProviders());
        const id = setTimeout(() => setInjected(listInjectedProviders()), 400);
        return () => clearTimeout(id);
    }, []);

    async function handleConnectInjected(detail: InjectedDetail) {
        setChainBusy("connecting");
        setChainErr(null);
        try {
            const s = await connectInjected(detail);
            setSession(s);
            if (s.chainId !== config.chainId) {
                setChainBusy("switching");
                const post = await ensureChain(s);
                setSession({ ...s, chainId: post });
            }
            setChainBusy("idle");
        } catch (e) {
            setChainErr(e instanceof Error ? e.message : String(e));
            setChainBusy("idle");
        }
    }

    async function handleConnectWalletConnect() {
        setChainBusy("connecting");
        setChainErr(null);
        try {
            const s = await connectWalletConnect();
            setSession(s);
            if (s.chainId !== config.chainId) {
                setChainBusy("switching");
                const post = await ensureChain(s);
                setSession({ ...s, chainId: post });
            }
            setChainBusy("idle");
        } catch (e) {
            setChainErr(e instanceof Error ? e.message : String(e));
            setChainBusy("idle");
        }
    }

    /**
     * Submit `EnrollmentRegistry.updateRoot(newRoot, newCommitments, attesterSig)`
     * via the user's wallet. The relayer is intentionally not on this path —
     * enrollment is a one-time, audit-cleaner action signed by the citizen.
     *
     * The attester pre-signs the EIP-191-wrapped digest
     *   inner = keccak256(abi.encode(oldRoot, newRoot,
     *                                keccak256(packed(newCommitments)),
     *                                chainId, address(this)))
     * server-side, so we pass `newCommitments` (and the resulting sig)
     * through verbatim.
     */
    async function handleChainSubmit() {
        if (!session || !registerResult || !oprfResult || !passkey) return;
        setChainBusy("submitting");
        setChainErr(null);
        try {
            if (session.chainId !== config.chainId) {
                setChainBusy("switching");
                const post = await ensureChain(session);
                setSession({ ...session, chainId: post });
                if (post !== config.chainId) {
                    setChainErr(t("enroll.chain.wrongChain"));
                    setChainBusy("idle");
                    return;
                }
            }

            // Simulate against our own RPC for proper gas estimation +
            // named-revert decoding.
            const { publicClient } = await import("../lib/chain");
            const { request } = await publicClient.simulateContract({
                account: session.address,
                address: config.enrollmentRegistry,
                abi: enrollmentRegistryAbi,
                functionName: "updateRoot",
                args: [
                    registerResult.newRoot,
                    registerResult.newCommitments,
                    registerResult.attesterSig,
                ],
            });
            let gas = request.gas;
            if (!gas) {
                gas = await publicClient.estimateContractGas({
                    account: session.address,
                    address: config.enrollmentRegistry,
                    abi: enrollmentRegistryAbi,
                    functionName: "updateRoot",
                    args: [
                        registerResult.newRoot,
                        registerResult.newCommitments,
                        registerResult.attesterSig,
                    ],
                });
            }
            const gasBuf = (gas * 125n) / 100n;

            setChainBusy("submitting");
            const txHash = await session.client.writeContract({
                ...request,
                gas: gasBuf,
                account: session.address,
                chain: config.chain,
            });
            setChainBusy("mining");
            const receipt = await publicClient.waitForTransactionReceipt({
                hash: txHash,
            });
            if (receipt.status !== "success") {
                setChainErr(t("enroll.chain.reverted"));
                setChainBusy("idle");
                return;
            }
            setChainTx(txHash);

            // Now persist the enrollment locally and reveal the mnemonic.
            const payload: EnrollmentPayload = {
                enrollmentSecret: oprfResult.s,
                oprfOutputN: hexEncode(oprfResult.N),
                merklePath: registerResult.merklePath,
                merklePathIndices: registerResult.merklePathIndices,
            };
            const ciphertext = await wrapPayload(payload, passkey.prfOutput);
            await putEnrollment({
                version: 1,
                commitment: oprfResult.s,
                leafIndex: registerResult.leafIndex,
                credentialId: hexEncode(passkey.credentialId),
                ciphertext,
            });
            setMnemonic(mnemonicFromN(oprfResult.N));
            setChainBusy("idle");
        } catch (e) {
            setChainErr(friendlyChainError(e, t));
            setChainBusy("idle");
        }
    }

    async function handleDisconnect() {
        const { disconnectWallet } = await import("../lib/wallet");
        await disconnectWallet(session);
        clearSession();
    }

    async function onFile(file: File) {
        setParseErr(null);
        try {
            const bytes = new Uint8Array(await file.arrayBuffer());
            const p = parseP7s(bytes);
            if (!tinuaPrefixOk(p)) {
                setParseErr(t("enroll.upload.wrongPrefix"));
                return;
            }
            setP7sBytes(bytes);
            setParsed(p);
        } catch (e) {
            setParseErr(
                t("enroll.upload.parseError", {
                    detail: e instanceof Error ? e.message : String(e),
                }),
            );
        }
    }

    async function createPasskey() {
        if (!parsed) return;
        setPasskeyBusy(true);
        setPasskeyErr(null);
        try {
            const userId = crypto.getRandomValues(new Uint8Array(16));
            const userName = `crisp-qes-v2-${Date.now()}`;
            const result = await registerPasskey(
                "CRISP-QES v2",
                userId,
                userName,
                userName,
            );
            setPasskey(result);
        } catch (e) {
            setPasskeyErr(e instanceof Error ? e.message : String(e));
        } finally {
            setPasskeyBusy(false);
        }
    }

    async function runOprf() {
        if (!parsed || !p7sBytes || !passkey) return;
        setOprfBusy(true);
        setOprfErr(null);
        try {
            const rn = rnokppBytes(parsed);
            const { blind: r, blindedElement } = blind(rn);
            const resp = await oprfBlindEval(blindedElement, p7sBytes);
            const ok = verifyBlindEval(blindedElement, {
                serverPubkey: hexDecode(resp.oprfPubkey),
                evaluatedElement: hexDecode(resp.Y),
                proof: hexDecode(resp.proof),
            });
            if (!ok) {
                setOprfErr(t("enroll.oprf.dleqInvalid"));
                return;
            }
            const N = unblind(hexDecode(resp.Y), r);
            // s is BOTH the enrollment secret AND the on-chain Merkle leaf
            // AND what the OPRF service stores as `commitment`.
            const s = await pedersenS(N);
            setOprfResult({ N, blindedElement, s });
        } catch (e) {
            setOprfErr(e instanceof Error ? e.message : String(e));
        } finally {
            setOprfBusy(false);
        }
    }

    async function runRegister() {
        if (!oprfResult || !passkey) return;
        setRegisterBusy(true);
        setRegisterErr(null);
        try {
            // Server-side guard: backend recomputes pedersen([N_hi,N_lo],0)
            // and checks it equals `commitment` (= s). So we must send N too.
            const r = await oprfRegister({
                commitment: oprfResult.s,
                blindedInputUsed: oprfResult.blindedElement,
                unblindedOutput: oprfResult.N,
            });

            // Per team-lead: enrollment-time root update is user-signed
            // via WalletConnect (NOT relayer-sponsored). We surface the
            // OPRF response here; the on-chain step (handleChainSubmit)
            // performs the EnrollmentRegistry.updateRoot call and only
            // then persists the local enrollment + reveals the mnemonic.
            setRegisterResult({
                merklePath: r.merklePath,
                merklePathIndices: r.merklePathIndices,
                leafIndex: r.leafIndex,
                newRoot: r.newRoot,
                newCommitments: r.newCommitments,
                attesterSig: r.attesterSig,
            });
        } catch (e) {
            setRegisterErr(e instanceof Error ? e.message : String(e));
        } finally {
            setRegisterBusy(false);
        }
    }

    return (
        <section className="section">
            <button className="btn--link" onClick={onBack} type="button">
                ← {t("enroll.back")}
            </button>
            <h2 className="section__title" style={{ marginTop: 8 }}>
                {t("enroll.heading")}
            </h2>
            <p className="note" style={{ marginBottom: 24 }}>
                {t("enroll.intro")}
            </p>

            <ol className="steps">
                {(["upload", "passkey", "oprf", "register", "backup"] as const).map(
                    (k) => {
                        const isActive = stage === k;
                        return (
                            <li
                                key={k}
                                className={
                                    "steps__item " +
                                    (isActive ? "steps__item--active" : "")
                                }
                            >
                                {t(`enroll.steps.${k}`)}
                            </li>
                        );
                    },
                )}
            </ol>

            {/* 1. Upload */}
            <div className="panel">
                <p className="panel__title">{t("enroll.upload.title")}</p>
                <p className="note">{t("enroll.upload.intro")}</p>
                <DropZone onFile={onFile} />
                {parseErr ? <p className="error-line">{parseErr}</p> : null}
                {parsed ? (
                    <p className="tag-ok">✓ {t("enroll.upload.parsed")}</p>
                ) : null}
            </div>

            {/* 2. Passkey */}
            {parsed ? (
                <div className="panel">
                    <p className="panel__title">{t("enroll.passkey.title")}</p>
                    <p className="note">{t("enroll.passkey.intro")}</p>
                    {!probe.available ? (
                        <p className="error-line">
                            {t("enroll.passkey.unsupported")}
                            {probe.reason ? ` — ${probe.reason}` : ""}
                        </p>
                    ) : passkey ? (
                        <p className="tag-ok">✓ {t("enroll.passkey.created")}</p>
                    ) : (
                        <div className="actions">
                            <button
                                className="btn btn--accent"
                                type="button"
                                onClick={createPasskey}
                                disabled={passkeyBusy}
                            >
                                {passkeyBusy
                                    ? t("enroll.passkey.creating")
                                    : t("enroll.passkey.create")}
                            </button>
                        </div>
                    )}
                    {passkeyErr ? (
                        <p className="error-line">
                            {t("enroll.passkey.error", { detail: passkeyErr })}
                        </p>
                    ) : null}
                </div>
            ) : null}

            {/* 3. OPRF */}
            {parsed && passkey ? (
                <div className="panel">
                    <p className="panel__title">{t("enroll.oprf.title")}</p>
                    <p className="note">{t("enroll.oprf.intro")}</p>
                    {oprfResult ? (
                        <dl>
                            <div className="field-row">
                                <dt>{t("enroll.oprf.commit")}</dt>
                                <dd className="mono">{oprfResult.s}</dd>
                            </div>
                        </dl>
                    ) : oprfBusy ? (
                        <p className="progress">
                            {t("enroll.oprf.running")}
                            <span className="progress__line">
                                <span />
                            </span>
                        </p>
                    ) : (
                        <div className="actions">
                            <button
                                className="btn btn--accent"
                                type="button"
                                onClick={runOprf}
                            >
                                {t("enroll.oprf.running")}
                            </button>
                        </div>
                    )}
                    {oprfErr ? (
                        <p className="error-line">
                            {t("enroll.oprf.error", { detail: oprfErr })}
                        </p>
                    ) : null}
                </div>
            ) : null}

            {/* 4. Register */}
            {oprfResult && passkey ? (
                <div className="panel">
                    <p className="panel__title">{t("enroll.register.title")}</p>
                    <p className="note">{t("enroll.register.intro")}</p>
                    {registerResult ? (
                        <dl>
                            <div className="field-row">
                                <dt>{t("enroll.register.newRoot")}</dt>
                                <dd className="mono">{registerResult.newRoot}</dd>
                            </div>
                            <div className="field-row">
                                <dt>{t("enroll.register.leafIndex")}</dt>
                                <dd className="mono">{registerResult.leafIndex}</dd>
                            </div>
                        </dl>
                    ) : registerBusy ? (
                        <p className="progress">
                            {t("enroll.register.running")}
                            <span className="progress__line">
                                <span />
                            </span>
                        </p>
                    ) : (
                        <div className="actions">
                            <button
                                className="btn btn--accent"
                                type="button"
                                onClick={runRegister}
                            >
                                {t("enroll.register.submit")}
                            </button>
                        </div>
                    )}
                    {registerErr ? (
                        <p className="error-line">
                            {t("enroll.register.error", { detail: registerErr })}
                        </p>
                    ) : null}
                </div>
            ) : null}

            {/* 4b. On-chain — user-signed via WalletConnect */}
            {registerResult && !chainTx ? (
                <div className="panel">
                    <p className="panel__title">{t("enroll.chain.title")}</p>
                    <p className="note">{t("enroll.chain.intro")}</p>

                    {!session ? (
                        <>
                            <ul className="wallet-picker">
                                {injected.map((d) => (
                                    <li key={d.info.uuid}>
                                        <button
                                            className="wallet-pick"
                                            type="button"
                                            onClick={() => handleConnectInjected(d)}
                                            disabled={chainBusy === "connecting"}
                                        >
                                            {d.info.icon ? (
                                                <img
                                                    className="wallet-pick__icon"
                                                    src={d.info.icon}
                                                    alt=""
                                                    width={28}
                                                    height={28}
                                                />
                                            ) : (
                                                <span className="wallet-pick__icon wallet-pick__icon--blank" />
                                            )}
                                            <span className="wallet-pick__body">
                                                <span className="wallet-pick__name">
                                                    {d.info.name}
                                                </span>
                                                <span className="wallet-pick__hint">
                                                    {t("enroll.chain.injectedHint")}
                                                </span>
                                            </span>
                                        </button>
                                    </li>
                                ))}
                                <li>
                                    <button
                                        className="wallet-pick"
                                        type="button"
                                        onClick={handleConnectWalletConnect}
                                        disabled={chainBusy === "connecting"}
                                    >
                                        <span
                                            className="wallet-pick__icon wallet-pick__icon--wc"
                                            aria-hidden
                                        >
                                            WC
                                        </span>
                                        <span className="wallet-pick__body">
                                            <span className="wallet-pick__name">
                                                {t("enroll.chain.walletConnect")}
                                            </span>
                                            <span className="wallet-pick__hint">
                                                {t("enroll.chain.walletConnectHint")}
                                            </span>
                                        </span>
                                    </button>
                                </li>
                            </ul>
                        </>
                    ) : (
                        <>
                            <dl>
                                <div className="field-row">
                                    <dt>{t("enroll.chain.wallet")}</dt>
                                    <dd className="mono">
                                        {session.label} · {session.address.slice(0, 6)}
                                        …{session.address.slice(-4)}{" "}
                                        <button
                                            className="btn--link"
                                            type="button"
                                            onClick={handleDisconnect}
                                            disabled={
                                                chainBusy === "submitting" ||
                                                chainBusy === "mining"
                                            }
                                        >
                                            {t("enroll.chain.disconnect")}
                                        </button>
                                    </dd>
                                </div>
                                <div className="field-row">
                                    <dt>{t("enroll.chain.chain")}</dt>
                                    <dd className="mono">
                                        {session.chainId === config.chainId ? (
                                            <span className="tag-ok">
                                                {config.chain.name} ({config.chainId})
                                            </span>
                                        ) : (
                                            <span className="tag-bad">
                                                {t("enroll.chain.wrongChain")}
                                            </span>
                                        )}
                                    </dd>
                                </div>
                            </dl>
                            <div className="actions">
                                <button
                                    className="btn btn--accent"
                                    type="button"
                                    onClick={handleChainSubmit}
                                    disabled={
                                        chainBusy === "submitting" ||
                                        chainBusy === "mining" ||
                                        chainBusy === "switching"
                                    }
                                >
                                    {chainBusy === "submitting"
                                        ? t("enroll.chain.signing")
                                        : chainBusy === "mining"
                                          ? t("enroll.chain.mining")
                                          : t("enroll.chain.submit")}
                                </button>
                            </div>
                        </>
                    )}

                    {chainErr ? (
                        <p className="error-line">
                            {t("enroll.chain.error", { detail: chainErr })}
                        </p>
                    ) : null}
                </div>
            ) : null}

            {/* 5. Backup — only after the chain step lands. */}
            {mnemonic ? (
                <div className="panel">
                    {chainTx ? (
                        <p className="note mono">
                            {t("enroll.chain.tx")}: {chainTx}
                        </p>
                    ) : null}
                    <p className="panel__title">{t("enroll.backup.title")}</p>
                    <p className="note">{t("enroll.backup.intro")}</p>
                    <p className="note text-warn">{t("enroll.backup.warning")}</p>
                    {mnemonicRevealed ? (
                        <p className="mono" style={{ fontSize: 15, lineHeight: 1.7 }}>
                            {mnemonic}
                        </p>
                    ) : null}
                    <div className="actions">
                        <button
                            className="btn btn--ghost"
                            type="button"
                            onClick={() => setMnemonicRevealed((v) => !v)}
                        >
                            {mnemonicRevealed
                                ? t("enroll.backup.hide")
                                : t("enroll.backup.show")}
                        </button>
                        <button
                            className="btn btn--accent"
                            type="button"
                            onClick={onDone}
                            disabled={!mnemonicRevealed}
                            title={
                                mnemonicRevealed
                                    ? undefined
                                    : t("enroll.backup.show")
                            }
                        >
                            {t("enroll.backup.saved")}
                        </button>
                    </div>
                </div>
            ) : null}
        </section>
    );
}

// Map EnrollmentRegistry custom reverts + common provider errors to
// translated copy.
function friendlyChainError(err: unknown, t: (k: string) => string): string {
    if (err instanceof BaseError) {
        const reverted = err.walk(
            (e) => e instanceof ContractFunctionRevertedError,
        );
        if (reverted instanceof ContractFunctionRevertedError) {
            const name = reverted.data?.errorName;
            switch (name) {
                case "BadSignature":
                    return t("enroll.chain.errors.badSignature");
                case "EmptyBatch":
                    return t("enroll.chain.errors.emptyBatch");
                case "NotAdmin":
                    return t("enroll.chain.errors.notAdmin");
                case "ZeroAddress":
                    return t("enroll.chain.errors.zeroAddress");
                default:
                    return (
                        reverted.shortMessage ??
                        t("enroll.chain.errors.unknown")
                    );
            }
        }
        return err.shortMessage ?? err.message;
    }
    if (err && typeof err === "object" && "code" in err) {
        const code = (err as { code?: number }).code;
        if (code === 4001) return t("enroll.chain.errors.userRejected");
    }
    return err instanceof Error ? err.message : String(err);
}
