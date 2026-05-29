// 5-step enrollment flow.
//
// 0. Download a small binding file containing
//    `"CRISP_QES_V2_ENROLL::" || epoch_day_be8` and sign it in Diia.
// 1. Upload the .p7s, extract RNOKPP from subjectSerial (after `TINUA-`).
// 2. Blind RNOKPP, call OPRF /blind-eval, verify DLEQ, unblind to obtain
//    `N`. Pedersen-derive `s = pedersen([N_hi, N_lo], 0)` — both the
//    enrollment secret AND the on-chain leaf AND the OPRF commitment.
// 3. Call OPRF /register with the commitment to get Merkle path,
//    newCommitments, and attesterSig. Submit
//    `EnrollmentRegistry.updateRoot(newRoot, newCommitments[],
//    attesterSig)` via the user's wallet (WalletConnect or injected).
// 4. Create a Passkey + read PRF output, AES-GCM-wrap the local payload
//    using HKDF(PRF), persist to IndexedDB.
//
// Recovery model (per /tmp/recovery-design.md, #51, and v2 spec §3.4
// patched at d4bb63d): v2 has exactly one recovery primitive — Passkey
// cloud sync. The BIP-39 mnemonic UI and `lib/bip39Recovery.ts` were
// removed (see commit log). v3 epoch rotation is the universal recovery
// primitive — lose everything, wait for next epoch, re-enroll with
// fresh Diia. No within-epoch fallback flow is shipped because every
// candidate (mnemonic, multi-Passkey ceremony, QES-anchored re-derive,
// social recovery, server backup) either duplicated the Diia anchor or
// added attack surface for a function epoch rotation provides for free.

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
import { buildEnrollmentBindingBytes } from "../lib/enrollmentBinding";
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
import { submitEnrollment } from "../lib/relayer";
import { config } from "../config";

interface Props {
    onBack: () => void;
    onDone: () => void;
}

type Stage =
    | "binding"
    | "upload"
    | "oprf"
    | "register"
    | "chain"
    | "passkey"
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

    // Step 0 — Diia binding file. Same UX as the MVP Sign page: download,
    // sign in Diia, upload. The bytes are NOT yet checked against
    // `signedAttrs.messageDigest` by the v2 OPRF (see oprf/attestation.ts
    // TODO), so this step is currently UX-only but forward-compatible with
    // the v2.1-prod attestation pin.
    const [bindingDownloaded, setBindingDownloaded] = useState(false);
    const [bindingExpanded, setBindingExpanded] = useState(false);

    const [p7sBytes, setP7sBytes] = useState<Uint8Array | null>(null);
    const [parsed, setParsed] = useState<ParsedP7s | null>(null);
    const [parseErr, setParseErr] = useState<string | null>(null);

    // Passkey now sits AFTER the on-chain step (#48 UX review). A failed
    // OPRF / commitment / chain submit no longer leaves a dangling
    // credential on the authenticator: the citizen only ever sees the
    // create-passkey prompt once enrollment is irrevocably committed.
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

    // On-chain step. #55 wallet-presence detection: the default path is
    // relayer-submitted (citizen never touches ETH). Wallet-self-submit
    // is preserved as an opt-in. The mode toggle lives inside the chain
    // panel; switching modes mid-flight is gated on chainBusy so we
    // don't strand a request.
    const { session, setSession, clearSession } = useWallet();
    const [injected, setInjected] = useState<InjectedDetail[]>([]);
    const [chainMode, setChainMode] = useState<"relayer" | "wallet">("relayer");
    const [chainBusy, setChainBusy] = useState<
        "idle" | "connecting" | "switching" | "submitting" | "mining"
    >("idle");
    const [chainErr, setChainErr] = useState<string | null>(null);
    const [chainTx, setChainTx] = useState<`0x${string}` | null>(null);

    const [stage, setStage] = useState<Stage>("binding");

    // Auto-advance the visible "current step" based on which artifacts
    // exist. 5-step sequence (see file header):
    //   binding → upload → oprf → register → chain → passkey.
    useEffect(() => {
        if (passkey) setStage("passkey");
        else if (chainTx) setStage("passkey");
        else if (registerResult) setStage("chain");
        else if (oprfResult) setStage("register");
        else if (parsed) setStage("oprf");
        else if (bindingDownloaded) setStage("upload");
        else setStage("binding");
    }, [
        bindingDownloaded,
        parsed,
        oprfResult,
        registerResult,
        chainTx,
        passkey,
    ]);

    useEffect(() => {
        startInjectedDiscovery();
        setInjected(listInjectedProviders());
        const id = setTimeout(() => setInjected(listInjectedProviders()), 400);
        return () => clearTimeout(id);
    }, []);

    // R3-5 intermediate ship — auto-chain server-side steps (OPRF →
    // register) so the citizen only confronts a button at points where
    // they actually make a decision: binding-download, .p7s drop,
    // wallet-connect, wallet-sign, passkey-tap. The OPRF call and the
    // ciphernode register round-trip carry no decision — the citizen
    // committed to enrollment at .p7s upload. Errors break the chain
    // and surface a Retry button so control is preserved on the unhappy
    // path. Survives #55 cleanly (the wallet-presence rework keeps the
    // same auto-chain logic and additionally collapses the chain step).
    useEffect(() => {
        if (parsed && p7sBytes && !oprfResult && !oprfBusy && !oprfErr) {
            void runOprf();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [parsed, p7sBytes, oprfResult, oprfBusy, oprfErr]);

    useEffect(() => {
        if (oprfResult && !registerResult && !registerBusy && !registerErr) {
            void runRegister();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [oprfResult, registerResult, registerBusy, registerErr]);

    // #55 — auto-fire relayer submit when in relayer mode (default).
    // The citizen never touches ETH on the happy path. Wallet mode is
    // opt-in (see chain panel JSX below). Same idempotency gate as the
    // OPRF/register effects: requires registerResult, no existing tx,
    // not already busy, no error.
    useEffect(() => {
        if (
            chainMode === "relayer" &&
            registerResult &&
            !chainTx &&
            chainBusy === "idle" &&
            !chainErr
        ) {
            void runRelayerSubmit();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [chainMode, registerResult, chainTx, chainBusy, chainErr]);

    /** Step 0: write the binding file to disk for Diia. */
    function handleDownloadBinding() {
        const bytes = buildEnrollmentBindingBytes();
        // Copy into a fresh ArrayBuffer (not SharedArrayBuffer) so the
        // Blob constructor type-checks under our strict DOM lib. Mirrors
        // the pattern from `packages/web/src/pages/Sign.tsx`.
        const ab = new ArrayBuffer(bytes.byteLength);
        new Uint8Array(ab).set(bytes);
        const blob = new Blob([ab], { type: "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "crisp-qes-v2-enrollment-binding.bin";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 0);
        setBindingDownloaded(true);
    }

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
     * #55 — relayer-default path. POST the OPRF service's attester
     * signature to the v2 relayer, which signs and submits the
     * `EnrollmentRegistry.updateRoot(...)` transaction on the citizen's
     * behalf. The citizen never sees a wallet picker, never pays gas.
     *
     * Pre-#55 the comment on `handleChainSubmit` claimed enrollment was
     * "intentionally not on the relayer path" for audit cleanliness;
     * post-#55 the user's call is to prioritise zero-friction onboarding
     * (citizens are not crypto users; demanding a wallet at enrollment
     * loses 95 % of them at step 0). The audit story shifts to "citizen
     * actively chose relayer; wallet-self-submit available for those who
     * want it" — surfaced via the mode toggle in the chain panel.
     */
    async function runRelayerSubmit() {
        if (!registerResult) return;
        setChainBusy("submitting");
        setChainErr(null);
        try {
            const r = await submitEnrollment({
                newRoot: registerResult.newRoot,
                newCommitments: registerResult.newCommitments,
                signature: registerResult.attesterSig,
            });
            if (!r.ok) {
                setChainErr(
                    r.detail ?? r.code ?? t("enroll.chain.errors.unknown"),
                );
                setChainBusy("idle");
                return;
            }
            setChainTx(r.txHash);
            setChainBusy("idle");
        } catch (e) {
            setChainErr(e instanceof Error ? e.message : String(e));
            setChainBusy("idle");
        }
    }

    /**
     * Wallet-self-submit path (opt-in via the chain panel mode toggle).
     * The attester pre-signs the EIP-191-wrapped digest
     *   inner = keccak256(abi.encode(oldRoot, newRoot,
     *                                keccak256(packed(newCommitments)),
     *                                chainId, address(this)))
     * server-side, so we pass `newCommitments` (and the resulting sig)
     * through verbatim regardless of who broadcasts the tx.
     */
    async function handleChainSubmit() {
        if (!session || !registerResult || !oprfResult) return;
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
            setChainBusy("idle");
            // Note: passkey creation + local persist run in
            // `handleCreatePasskey` (step 4). If we fail here, no
            // credential was minted; the citizen can retry the wallet
            // step. No mnemonic derivation — recovery in v2 is Passkey
            // cloud sync only; from v3 onward it's yearly re-enrollment
            // via Diia (see v2 spec §3.4 + §3.5).
        } catch (e) {
            setChainErr(friendlyChainError(e, t));
            setChainBusy("idle");
        }
    }

    /**
     * Step 4: now that the enrollment root is on-chain, mint the Passkey,
     * wrap the payload, persist to IndexedDB. If this step fails, the
     * enrollment is still good on-chain — the citizen can re-enter the
     * app and retry locally; the OPRF service's
     * `/enrollment/:commitment/path` endpoint reconstructs everything
     * else from the existing on-chain commitment.
     *
     * No mnemonic derivation — recovery in v2 is Passkey cloud sync
     * only (see v2 spec §3.4 patched at d4bb63d).
     */
    async function handleCreatePasskey() {
        if (!oprfResult || !registerResult || !chainTx) return;
        setPasskeyBusy(true);
        setPasskeyErr(null);
        try {
            const userId = crypto.getRandomValues(new Uint8Array(16));
            const userName = `crisp-qes-v2-${Date.now()}`;
            const pk = await registerPasskey(
                "CRISP-QES v2",
                userId,
                userName,
                userName,
            );
            const payload: EnrollmentPayload = {
                enrollmentSecret: oprfResult.s,
                oprfOutputN: hexEncode(oprfResult.N),
                merklePath: registerResult.merklePath,
                merklePathIndices: registerResult.merklePathIndices,
            };
            const ciphertext = await wrapPayload(payload, pk.prfOutput);
            await putEnrollment({
                version: 1,
                commitment: oprfResult.s,
                leafIndex: registerResult.leafIndex,
                credentialId: hexEncode(pk.credentialId),
                ciphertext,
            });
            setPasskey(pk);
        } catch (e) {
            setPasskeyErr(e instanceof Error ? e.message : String(e));
        } finally {
            setPasskeyBusy(false);
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

    async function runOprf() {
        if (!parsed || !p7sBytes) return;
        setOprfBusy(true);
        setOprfErr(null);
        try {
            const rn = rnokppBytes(parsed);
            const { blind: r, blindedElement } = blind(rn);
            const resp = await oprfBlindEval(blindedElement, p7sBytes);
            const ok = verifyBlindEval(blindedElement, {
                serverPubkey: hexDecode(resp.oprfPubkey),
                evaluatedElement: hexDecode(resp.Y),
                // #53: `resp.proof` is already a normalised 64-byte
                // buffer (see `oprfClient.coerceProof`). The earlier
                // `hexDecode(resp.proof)` call assumed the wire shape was
                // a flat hex string and crashed with "t.slice is not a
                // function" against the current server's `{ c, s }`
                // object shape.
                proof: resp.proof,
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
        if (!oprfResult) return;
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
            // then mints the Passkey + persists the local enrollment.
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

            {/*
             * Hoisted primary CTA — same pattern as Landing's RED-3 fix.
             * The enrollment flow's first user action is downloading the
             * binding file; without this hoist the action sits at y≈974 px
             * on iPhone SE (offscreen by 1.46 screens). See R3-1 in
             * benchmarker's round-2 report.
             * Auto-hides once downloaded so the user's next signal becomes
             * "scroll to the upload zone" rather than "this button is still
             * here, do I tap it again?".
             */}
            {!bindingDownloaded ? (
                <div className="cta-row cta-row--hoisted">
                    <button
                        className="btn btn--accent"
                        type="button"
                        onClick={handleDownloadBinding}
                    >
                        {t("enroll.binding.download")}
                    </button>
                </div>
            ) : null}

            <ol className="steps">
                {(
                    [
                        { key: "binding", system: false },
                        { key: "upload", system: false },
                        // OPRF + register fire automatically (#68 auto-chain).
                        // Chain (the on-chain submit) is system-handled too on
                        // the relayer-default path (#55); wallet path is opt-in.
                        // Marking them as `system` dims the row visually so the
                        // citizen reads the list as "I do these three; we
                        // handle the rest" rather than "5 things to do".
                        // See YEL-5 in bench/ux-results-2026-05-29.md.
                        { key: "oprf", system: true },
                        { key: "register", system: chainMode === "relayer" },
                        { key: "passkey", system: false },
                    ] as const
                ).map(({ key, system }) => {
                    const isActive = stage === key;
                    const cls = [
                        "steps__item",
                        isActive ? "steps__item--active" : "",
                        system ? "steps__item--system" : "",
                    ]
                        .filter(Boolean)
                        .join(" ");
                    return (
                        <li key={key} className={cls}>
                            {t(`enroll.steps.${key}`)}
                            {system ? (
                                <span
                                    className="steps__system-tag"
                                    aria-label={t("enroll.steps.systemTag")}
                                >
                                    {" "}
                                    {t("enroll.steps.systemTag")}
                                </span>
                            ) : null}
                        </li>
                    );
                })}
            </ol>

            {/* 0. Binding file — what the citizen signs in Diia. */}
            <div className="panel">
                <p className="panel__title">{t("enroll.binding.title")}</p>
                <p className="note">{t("enroll.binding.intro")}</p>
                <div className="actions">
                    <button
                        className="btn btn--accent"
                        type="button"
                        onClick={handleDownloadBinding}
                    >
                        {t("enroll.binding.download")}
                    </button>
                </div>
                {bindingDownloaded ? (
                    <p className="note" style={{ marginTop: 12 }}>
                        <span className="tag-ok">✓</span>{" "}
                        {t("enroll.binding.afterDownload")}
                    </p>
                ) : null}
                <p style={{ marginTop: 14 }}>
                    <button
                        className="btn--link"
                        type="button"
                        onClick={() => setBindingExpanded((v) => !v)}
                        aria-expanded={bindingExpanded}
                    >
                        {bindingExpanded
                            ? t("enroll.binding.whatIsThisHide")
                            : t("enroll.binding.whatIsThis")}
                    </button>
                </p>
                {bindingExpanded ? (
                    <p className="note">{t("enroll.binding.details")}</p>
                ) : null}
            </div>

            {/* 1. Upload — open as soon as the binding is downloaded, but
                the user is free to upload a .p7s prepared elsewhere. */}
            <div className="panel">
                <p className="panel__title">{t("enroll.upload.title")}</p>
                <p className="note">{t("enroll.upload.intro")}</p>
                <DropZone onFile={onFile} />
                {parseErr ? <p className="error-line">{parseErr}</p> : null}
                {parsed ? (
                    <p className="tag-ok">✓ {t("enroll.upload.parsed")}</p>
                ) : null}
            </div>

            {/* 2. OPRF — auto-fires on `parsed`. Error surfaces Retry. */}
            {parsed ? (
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
                    ) : oprfErr ? (
                        <>
                            <p className="error-line">
                                {t("enroll.oprf.error", { detail: oprfErr })}
                            </p>
                            <div className="actions">
                                <button
                                    className="btn"
                                    type="button"
                                    onClick={() => {
                                        setOprfErr(null);
                                        void runOprf();
                                    }}
                                >
                                    {t("common.retry")}
                                </button>
                            </div>
                        </>
                    ) : (
                        <p className="progress">
                            {t("enroll.oprf.running")}
                            <span className="progress__line">
                                <span />
                            </span>
                        </p>
                    )}
                </div>
            ) : null}

            {/* 3. Register — auto-fires on `oprfResult`. Error surfaces Retry. */}
            {oprfResult ? (
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
                    ) : registerErr ? (
                        <>
                            <p className="error-line">
                                {t("enroll.register.error", { detail: registerErr })}
                            </p>
                            <div className="actions">
                                <button
                                    className="btn"
                                    type="button"
                                    onClick={() => {
                                        setRegisterErr(null);
                                        void runRegister();
                                    }}
                                >
                                    {t("common.retry")}
                                </button>
                            </div>
                        </>
                    ) : (
                        <p className="progress">
                            {t("enroll.register.running")}
                            <span className="progress__line">
                                <span />
                            </span>
                        </p>
                    )}
                </div>
            ) : null}

            {/* 4b. On-chain — #55 wallet-presence detection.
                Default = relayer-submitted (zero clicks for the citizen).
                Wallet-self-submit is an opt-in toggle inside the panel. */}
            {registerResult && !chainTx ? (
                <div className="panel">
                    <p className="panel__title">{t("enroll.chain.title")}</p>
                    <p className="note">
                        {chainMode === "relayer"
                            ? t("enroll.chain.relayerIntro")
                            : t("enroll.chain.intro")}
                    </p>

                    {chainMode === "relayer" ? (
                        <>
                            {chainErr ? (
                                <>
                                    <p className="error-line">
                                        {t("enroll.chain.error", {
                                            detail: chainErr,
                                        })}
                                    </p>
                                    <div className="actions">
                                        <button
                                            className="btn"
                                            type="button"
                                            onClick={() => {
                                                setChainErr(null);
                                                void runRelayerSubmit();
                                            }}
                                        >
                                            {t("common.retry")}
                                        </button>
                                    </div>
                                </>
                            ) : (
                                <p className="progress">
                                    {t("enroll.chain.relayerSubmitting")}
                                    <span className="progress__line">
                                        <span />
                                    </span>
                                </p>
                            )}
                            <p className="note" style={{ marginTop: 12 }}>
                                {t("enroll.chain.modeNotice")}
                            </p>
                            <p>
                                <button
                                    className="btn--link"
                                    type="button"
                                    onClick={() => {
                                        // Switching to wallet only makes sense
                                        // when nothing is in flight; chainBusy
                                        // gates the link.
                                        if (chainBusy !== "idle") return;
                                        setChainErr(null);
                                        setChainMode("wallet");
                                    }}
                                    disabled={chainBusy !== "idle"}
                                >
                                    {t("enroll.chain.useWallet")}
                                </button>
                            </p>
                        </>
                    ) : (
                        <>
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

                            {/* Common wallet-mode footer: chainErr surface
                                + disclosure copy + "back to relayer" link. */}
                            {chainErr ? (
                                <p className="error-line">
                                    {t("enroll.chain.error", {
                                        detail: chainErr,
                                    })}
                                </p>
                            ) : null}
                            <p className="note" style={{ marginTop: 12 }}>
                                {t("enroll.chain.modeNotice")}
                            </p>
                            <p>
                                <button
                                    className="btn--link"
                                    type="button"
                                    onClick={() => {
                                        // Switching away from wallet only when
                                        // no tx is in flight; chainBusy gates.
                                        if (chainBusy !== "idle") return;
                                        setChainErr(null);
                                        setChainMode("relayer");
                                    }}
                                    disabled={chainBusy !== "idle"}
                                >
                                    {t("enroll.chain.useRelayer")}
                                </button>
                            </p>
                        </>
                    )}
                </div>
            ) : null}

            {/* 4. Passkey — minted AFTER the chain step lands so a
                failed enrollment can't leave a dangling credential.
                The same handler wraps + persists the local payload.
                The recovery-tier disclosure (Passkey cloud sync is the
                only v2 recovery; v3 introduces yearly re-enrollment
                via Diia) is anchored on this panel — no separate
                Backup step. See file header for #51 rationale. */}
            {chainTx ? (
                <div className="panel">
                    <p className="note mono">
                        {t("enroll.chain.tx")}: {chainTx}
                    </p>
                    <p className="panel__title">{t("enroll.passkey.title")}</p>
                    <p className="note">{t("enroll.passkey.intro")}</p>
                    <p className="note">{t("enroll.passkey.recoveryNote")}</p>
                    {!probe.available ? (
                        <p className="error-line">
                            {t("enroll.passkey.unsupported")}
                            {probe.reason ? ` — ${probe.reason}` : ""}
                        </p>
                    ) : !passkey ? (
                        <div className="actions">
                            <button
                                className="btn btn--accent"
                                type="button"
                                onClick={handleCreatePasskey}
                                disabled={passkeyBusy}
                            >
                                {passkeyBusy
                                    ? t("enroll.passkey.creating")
                                    : t("enroll.passkey.create")}
                            </button>
                        </div>
                    ) : (
                        <div className="actions">
                            <p className="tag-ok" style={{ marginRight: 12 }}>
                                ✓ {t("enroll.passkey.created")}
                            </p>
                            <button
                                className="btn btn--accent"
                                type="button"
                                onClick={onDone}
                            >
                                {t("enroll.passkey.finish")}
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
