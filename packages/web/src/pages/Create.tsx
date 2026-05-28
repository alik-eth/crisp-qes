// Create a new petition.
//
// This page is the *only* place in the app that needs an EOA wallet —
// petition creation locks a refundable deposit and emits the creator's
// address on-chain. (Signing, in contrast, is walletless.) We use
// raw @walletconnect/ethereum-provider; viem's writeContract handles the
// rest. We mirror the contract's own validation (deposit, deadline,
// MAX_TEXT_BYTES, EmptyText) on the client so the user gets a clear error
// without spending gas.

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
    BaseError,
    ContractFunctionRevertedError,
    stringToBytes,
    toHex,
} from "viem";
import { config } from "../config";
import { petitionRegistryAbi } from "../lib/abi";
import {
    connectInjected,
    connectWalletConnect,
    ensureChain,
    disconnectWallet,
    listInjectedProviders,
    startInjectedDiscovery,
    type InjectedDetail,
    type WalletSession,
} from "../lib/wallet";
import { useWallet } from "../lib/walletContext";

interface Props {
    onBack: () => void;
    onCreated: (id: bigint, txHash: `0x${string}`) => void;
}

type Phase =
    | { kind: "idle" }
    | { kind: "connecting" }
    | { kind: "switching" }
    | { kind: "submitting" }
    | { kind: "mining"; txHash: `0x${string}` }
    | { kind: "error"; message: string };

function utf8ByteLength(s: string): number {
    return new TextEncoder().encode(s).length;
}

function shortAddr(addr: string): string {
    return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

// Build a value suitable for an <input type="datetime-local"> default:
// "now + 7 days", formatted as YYYY-MM-DDTHH:mm in the user's local TZ.
function defaultDeadlineLocal(): string {
    const d = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    const pad = (n: number) => String(n).padStart(2, "0");
    return (
        `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
        `T${pad(d.getHours())}:${pad(d.getMinutes())}`
    );
}

function localToEpochSecs(local: string): number {
    // datetime-local lacks a TZ designator; JS parses it as local time.
    return Math.floor(new Date(local).getTime() / 1000);
}

export function Create({ onBack, onCreated }: Props) {
    const { t } = useTranslation();

    const { session, setSession, clearSession } = useWallet();

    const [text, setText] = useState("");
    const [deadlineLocal, setDeadlineLocal] = useState(defaultDeadlineLocal());
    const [threshold, setThreshold] = useState("100");
    const [phase, setPhase] = useState<Phase>({ kind: "idle" });
    const [injected, setInjected] = useState<InjectedDetail[]>([]);

    const byteLen = useMemo(() => utf8ByteLength(text), [text]);

    const thresholdNum = useMemo(() => {
        const n = Number(threshold);
        if (!Number.isFinite(n)) return 0;
        return Math.floor(n);
    }, [threshold]);

    const deadlineEpoch = useMemo(
        () => (deadlineLocal ? localToEpochSecs(deadlineLocal) : 0),
        [deadlineLocal],
    );

    const validation = useMemo(() => {
        const errs: string[] = [];
        if (byteLen === 0) errs.push("emptyText");
        if (byteLen > config.maxTextBytes) errs.push("textTooLarge");
        if (!deadlineLocal || deadlineEpoch <= Math.floor(Date.now() / 1000) + 30) {
            errs.push("deadlineInPast");
        }
        if (!Number.isFinite(thresholdNum) || thresholdNum < 1) errs.push("thresholdInvalid");
        if (thresholdNum > 0xffffffff) errs.push("thresholdTooLarge");
        return errs;
    }, [byteLen, deadlineLocal, deadlineEpoch, thresholdNum]);

    const onTargetChain =
        session !== null && session.chainId === config.chainId;
    const phaseIdle = phase.kind === "idle" || phase.kind === "error";
    const canSubmit =
        validation.length === 0 && session !== null && onTargetChain && phaseIdle;

    // Why the submit button is greyed out — surfaced via `title` /
    // `aria-disabled-reason` so the user knows what to fix.
    const disabledReason: string | null = (() => {
        if (!phaseIdle) return null; // showing phase progress instead
        if (validation.length > 0)
            return t(`create.validation.${validation[0]}`);
        if (!session) return t("create.cta.needsWallet");
        if (!onTargetChain) return t("create.cta.wrongChain");
        return null;
    })();

    useEffect(() => {
        startInjectedDiscovery();
        // Browser wallets announce themselves synchronously, but some inject
        // a tick late. We re-read after a short delay so the picker shows
        // the full list on first render.
        setInjected(listInjectedProviders());
        const t = setTimeout(() => setInjected(listInjectedProviders()), 400);
        return () => clearTimeout(t);
    }, []);

    async function finishConnect(s: WalletSession) {
        setSession(s);
        if (s.chainId !== config.chainId) {
            setPhase({ kind: "switching" });
            try {
                const post = await ensureChain(s);
                setSession({ ...s, chainId: post });
            } catch (err) {
                setPhase({ kind: "error", message: friendlyError(err, t) });
                return;
            }
        }
        setPhase({ kind: "idle" });
    }

    async function handleConnectInjected(detail: InjectedDetail) {
        setPhase({ kind: "connecting" });
        try {
            const s = await connectInjected(detail);
            await finishConnect(s);
        } catch (err) {
            setPhase({ kind: "error", message: friendlyError(err, t) });
        }
    }

    async function handleConnectWalletConnect() {
        setPhase({ kind: "connecting" });
        try {
            const s = await connectWalletConnect();
            await finishConnect(s);
        } catch (err) {
            setPhase({ kind: "error", message: friendlyError(err, t) });
        }
    }

    async function handleDisconnect() {
        await disconnectWallet(session);
        clearSession();
        setPhase({ kind: "idle" });
    }

    async function handleSubmit() {
        if (!session) return;
        if (validation.length > 0) return;
        try {
            // Make sure we're on the right chain right before the write —
            // the user might have switched away in the wallet UI.
            if (session.chainId !== config.chainId) {
                setPhase({ kind: "switching" });
                const post = await ensureChain(session);
                setSession({ ...session, chainId: post });
                if (post !== config.chainId) {
                    setPhase({ kind: "error", message: t("create.errors.wrongChain") });
                    return;
                }
            }

            setPhase({ kind: "submitting" });
            const fullText = toHex(stringToBytes(text));

            // Simulate first against our public RPC. This (a) validates the
            // call and surfaces named reverts before the wallet popup, and
            // (b) produces a proper gas estimate so MetaMask doesn't fall
            // back to a too-low default when its built-in Base Sepolia RPC
            // can't simulate (which fails with "gas provided is too low").
            const { publicClient } = await import("../lib/chain");
            const { request } = await publicClient.simulateContract({
                account: session.address,
                address: config.registry,
                abi: petitionRegistryAbi,
                functionName: "createPetition",
                args: [fullText, BigInt(deadlineEpoch), thresholdNum],
                value: config.creationDepositWei,
            });

            // Compute a gas estimate with headroom. `request.gas` is set by
            // simulateContract when the chain supports `eth_estimateGas`; if
            // it isn't, we fall back to an explicit estimate. Add a 25%
            // buffer to absorb fullText-size variance and event topic costs.
            let gas: bigint | undefined = request.gas;
            if (!gas) {
                gas = await publicClient.estimateContractGas({
                    account: session.address,
                    address: config.registry,
                    abi: petitionRegistryAbi,
                    functionName: "createPetition",
                    args: [fullText, BigInt(deadlineEpoch), thresholdNum],
                    value: config.creationDepositWei,
                });
            }
            const gasWithBuffer = (gas * 125n) / 100n;

            const txHash = await session.client.writeContract({
                ...request,
                gas: gasWithBuffer,
                account: session.address,
                chain: config.chain,
            });

            setPhase({ kind: "mining", txHash });

            const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
            if (receipt.status !== "success") {
                setPhase({ kind: "error", message: t("create.errors.txReverted") });
                return;
            }
            // The contract assigns `id = nextPetitionId++`; rather than
            // parsing the PetitionCreated log, we read the latest id and
            // hand it to onCreated. The page's job is done at this point.
            try {
                const next = await publicClient.readContract({
                    address: config.registry,
                    abi: petitionRegistryAbi,
                    functionName: "nextPetitionId",
                });
                onCreated(next - 1n, txHash);
            } catch {
                onCreated(0n, txHash);
            }
        } catch (err) {
            setPhase({ kind: "error", message: friendlyError(err, t) });
        }
    }

    const phaseLabel: string | null = (() => {
        switch (phase.kind) {
            case "connecting":
                return t("create.phase.connecting");
            case "switching":
                return t("create.phase.switching");
            case "submitting":
                return t("create.phase.submitting");
            case "mining":
                return t("create.phase.mining");
            default:
                return null;
        }
    })();

    return (
        <section className="section">
            <p className="section__label">§ 04</p>
            <h2 className="section__title">{t("create.heading")}</h2>
            <p className="note" style={{ marginBottom: 24 }}>
                {t("create.intro")}
            </p>

            <div className="panel">
                <h3 className="panel__title">{t("create.form.title")}</h3>

                <label className="field-block">
                    <span className="field-block__label">
                        {t("create.form.text")}
                    </span>
                    <textarea
                        className="textarea"
                        rows={10}
                        value={text}
                        onChange={(e) => setText(e.target.value)}
                        placeholder={t("create.form.textPlaceholder")}
                        spellCheck
                    />
                    <span
                        className={
                            "field-block__hint " +
                            (byteLen > config.maxTextBytes ? "text-bad" : "")
                        }
                    >
                        {t("create.form.bytes", {
                            n: byteLen,
                            max: config.maxTextBytes,
                        })}
                    </span>
                </label>

                <label className="field-block">
                    <span className="field-block__label">
                        {t("create.form.deadline")}
                    </span>
                    <input
                        className="input"
                        type="datetime-local"
                        value={deadlineLocal}
                        onChange={(e) => setDeadlineLocal(e.target.value)}
                    />
                    <span className="field-block__hint">
                        {t("create.form.deadlineHint")}
                    </span>
                </label>

                <label className="field-block">
                    <span className="field-block__label">
                        {t("create.form.threshold")}
                    </span>
                    <input
                        className="input"
                        type="number"
                        min={1}
                        step={1}
                        value={threshold}
                        onChange={(e) => setThreshold(e.target.value)}
                    />
                    <span className="field-block__hint">
                        {t("create.form.thresholdHint")}
                    </span>
                </label>

                {validation.length > 0 ? (
                    <ul className="validation">
                        {validation.map((code) => (
                            <li key={code} className="text-bad">
                                {t(`create.validation.${code}`)}
                            </li>
                        ))}
                    </ul>
                ) : null}
            </div>

            <div className="panel">
                <h3 className="panel__title">{t("create.publish.title")}</h3>

                {!session ? (
                    <>
                        <p className="note">{t("create.wallet.needed")}</p>

                        <ul className="wallet-picker">
                            {injected.map((d) => (
                                <li key={d.info.uuid}>
                                    <button
                                        className="wallet-pick"
                                        type="button"
                                        onClick={() => handleConnectInjected(d)}
                                        disabled={phase.kind === "connecting"}
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
                                                {t("create.wallet.injectedHint")}
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
                                    disabled={phase.kind === "connecting"}
                                >
                                    <span className="wallet-pick__icon wallet-pick__icon--wc" aria-hidden>
                                        WC
                                    </span>
                                    <span className="wallet-pick__body">
                                        <span className="wallet-pick__name">
                                            {t("create.wallet.walletConnect")}
                                        </span>
                                        <span className="wallet-pick__hint">
                                            {t("create.wallet.walletConnectHint")}
                                        </span>
                                    </span>
                                </button>
                            </li>
                        </ul>

                        {injected.length === 0 ? (
                            <p className="note" style={{ marginTop: 12 }}>
                                {t("create.wallet.noInjected")}
                            </p>
                        ) : null}
                    </>
                ) : (
                    <dl>
                        <div className="field-row">
                            <dt>{t("create.wallet.connected")}</dt>
                            <dd className="mono">
                                {session.label} · {shortAddr(session.address)}{" "}
                                <button
                                    className="btn--link"
                                    type="button"
                                    onClick={handleDisconnect}
                                    disabled={
                                        phase.kind === "submitting" ||
                                        phase.kind === "mining"
                                    }
                                >
                                    {t("create.wallet.disconnect")}
                                </button>
                            </dd>
                        </div>
                        <div className="field-row">
                            <dt>{t("create.wallet.chain")}</dt>
                            <dd className="mono">
                                {onTargetChain ? (
                                    <span className="tag-ok">
                                        {config.chain.name} ({config.chainId})
                                    </span>
                                ) : (
                                    <span className="tag-bad">
                                        {t("create.wallet.wrongChain", {
                                            current: session.chainId,
                                            target: config.chainId,
                                        })}
                                    </span>
                                )}
                            </dd>
                        </div>
                    </dl>
                )}

                <p className="note" style={{ marginTop: 14 }}>
                    {t("create.deposit.oneLine")}
                </p>

                <div className="actions" style={{ marginTop: 18 }}>
                    <button
                        className="btn btn--accent"
                        type="button"
                        onClick={handleSubmit}
                        disabled={!canSubmit}
                        title={disabledReason ?? undefined}
                        aria-disabled={!canSubmit}
                    >
                        {phase.kind === "submitting" ||
                        phase.kind === "mining" ||
                        phase.kind === "switching"
                            ? t("create.submitting")
                            : t("create.submitWithDeposit")}
                    </button>
                    <button
                        className="btn btn--link"
                        type="button"
                        onClick={onBack}
                    >
                        {t("create.back")}
                    </button>
                </div>

                {disabledReason ? (
                    <p
                        className="note text-warn"
                        style={{ marginTop: 8 }}
                        role="status"
                    >
                        {disabledReason}
                    </p>
                ) : null}

                {phaseLabel ? (
                    <p className="progress">
                        {phaseLabel}
                        <span className="progress__line">
                            <span />
                        </span>
                    </p>
                ) : null}

                {phase.kind === "mining" ? (
                    <p className="note mono" style={{ marginTop: 8 }}>
                        {t("create.tx")}: {phase.txHash}
                    </p>
                ) : null}

                {phase.kind === "error" ? (
                    <p className="error-line">{phase.message}</p>
                ) : null}
            </div>

            <details className="disclosure">
                <summary className="disclosure__summary">
                    {t("create.privacy.title")}
                </summary>
                <p className="note">{t("create.privacy.body")}</p>
            </details>
        </section>
    );
}

// Map known revert names + common provider errors into translated copy.
function friendlyError(err: unknown, t: (k: string) => string): string {
    if (err instanceof BaseError) {
        const reverted = err.walk(
            (e) => e instanceof ContractFunctionRevertedError,
        );
        if (reverted instanceof ContractFunctionRevertedError) {
            const name = reverted.data?.errorName;
            switch (name) {
                case "WrongDeposit":
                    return t("create.errors.wrongDeposit");
                case "EmptyText":
                    return t("create.errors.emptyText");
                case "TextTooLarge":
                    return t("create.errors.textTooLarge");
                case "DeadlineInPast":
                    return t("create.errors.deadlineInPast");
                default:
                    return reverted.shortMessage ?? t("create.errors.unknown");
            }
        }
        return err.shortMessage ?? err.message;
    }
    if (err && typeof err === "object" && "code" in err) {
        const code = (err as { code?: number }).code;
        if (code === 4001) return t("create.errors.userRejected");
    }
    return err instanceof Error ? err.message : String(err);
}
