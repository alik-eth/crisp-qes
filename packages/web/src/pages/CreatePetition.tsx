import { useEffect, useState, useCallback } from "react";
import { useLocation, Link } from "wouter";
import { useTranslation } from "react-i18next";
import {
    formatEther,
    decodeEventLog,
    toBytes,
    toHex,
} from "viem";
import { config } from "../config.js";
import { petitionRegistryV2Abi } from "../lib/abi.js";
import { publicClient } from "../lib/chain.js";
import { readCreationDeposit } from "../lib/registry.js";
import { useWallet } from "../lib/walletContext.js";
import {
    startInjectedDiscovery,
    listInjectedProviders,
    connectInjected,
    connectWalletConnect,
    ensureChain,
    type WalletSession,
} from "../lib/wallet.js";

type Stage = "form" | "confirm" | "connect" | "submitting" | "mining" | "done" | "error";

export function CreatePetition() {
    const { t } = useTranslation();
    const [, navigate] = useLocation();
    const { session, setSession } = useWallet();

    const [title, setTitle] = useState("");
    const [body, setBody] = useState("");
    const [durationKey, setDurationKey] = useState("14");
    const [threshold, setThreshold] = useState(100);

    const [deposit, setDeposit] = useState<bigint | null>(null);
    const [depositErr, setDepositErr] = useState(false);

    const [stage, setStage] = useState<Stage>("form");
    const [errMsg, setErrMsg] = useState<string | null>(null);
    const [txHash, setTxHash] = useState<`0x${string}` | null>(null);
    const [newId, setNewId] = useState<bigint | null>(null);

    const durationOptions = [
        { key: "7", label: t("create.days7"), days: 7 },
        { key: "14", label: t("create.days14"), days: 14 },
        { key: "30", label: t("create.days30"), days: 30 },
        { key: "90", label: t("create.days90"), days: 90 },
    ];

    useEffect(() => {
        startInjectedDiscovery();
        let alive = true;
        void (async () => {
            try {
                const d = await readCreationDeposit();
                if (alive) setDeposit(d);
            } catch {
                if (alive) setDepositErr(true);
            }
        })();
        return () => {
            alive = false;
        };
    }, []);

    const durationDays =
        durationOptions.find((o) => o.key === durationKey)?.days ?? 14;
    const deadline = BigInt(
        Math.floor(Date.now() / 1000) + durationDays * 86400,
    );

    const titleTrim = title.trim();
    const bodyTrim = body.trim();
    const fullText = bodyTrim
        ? `${titleTrim}\n\n${bodyTrim}`
        : titleTrim;
    const fullTextBytes = toBytes(fullText);

    const valid =
        titleTrim.length > 0 &&
        titleTrim.length <= 200 &&
        fullTextBytes.length <= 64 * 1024 &&
        threshold >= 1 &&
        threshold <= 1_000_000;

    const onSubmit = useCallback(async () => {
        if (!valid || deposit === null) return;
        setErrMsg(null);
        if (!session) {
            setStage("connect");
            return;
        }
        await runSubmit(session);
    }, [valid, deposit, session]);

    const runSubmit = useCallback(
        async (s: WalletSession) => {
            if (deposit === null) return;
            setStage("submitting");
            setErrMsg(null);
            try {
                if (s.chainId !== config.chainId) {
                    const next = await ensureChain(s);
                    setSession({ ...s, chainId: next });
                    if (next !== config.chainId) {
                        setErrMsg(
                            `Switch your wallet to ${config.chain.name}.`,
                        );
                        setStage("error");
                        return;
                    }
                }

                const { request } = await publicClient.simulateContract({
                    account: s.address,
                    address: config.petitionRegistryV2,
                    abi: petitionRegistryV2Abi,
                    functionName: "createPetition",
                    args: [
                        toHex(fullTextBytes),
                        deadline,
                        threshold,
                    ],
                    value: deposit,
                });
                const hash = await s.client.writeContract({
                    ...request,
                    account: s.address,
                    chain: config.chain,
                });
                setTxHash(hash);
                setStage("mining");

                const receipt = await publicClient.waitForTransactionReceipt({
                    hash,
                });
                if (receipt.status !== "success") {
                    setErrMsg("Transaction reverted.");
                    setStage("error");
                    return;
                }

                let foundId: bigint | null = null;
                for (const log of receipt.logs) {
                    if (
                        log.address.toLowerCase() !==
                        config.petitionRegistryV2.toLowerCase()
                    )
                        continue;
                    try {
                        const dec = decodeEventLog({
                            abi: petitionRegistryV2Abi,
                            data: log.data,
                            topics: log.topics,
                        });
                        if (dec.eventName === "PetitionCreated") {
                            foundId = (dec.args as { id: bigint }).id;
                            break;
                        }
                    } catch {
                        // not this event
                    }
                }
                setNewId(foundId);
                setStage("done");
            } catch (e) {
                setErrMsg(e instanceof Error ? e.message : String(e));
                setStage("error");
            }
        },
        [deposit, fullTextBytes, deadline, threshold, setSession],
    );

    return (
        <section className="create">
            <div className="detail__crumbs">
                <Link href="/petitions">{t("create.back")}</Link>
            </div>
            <h1 style={{ marginBottom: 24 }}>{t("create.heading")}</h1>

            {stage === "form" || stage === "confirm" || stage === "error" ? (
                <div className="form">
                    <Field label={t("create.title")}>
                        <input
                            type="text"
                            value={title}
                            onChange={(e) => setTitle(e.target.value)}
                            placeholder={t("create.titlePlaceholder")}
                            maxLength={200}
                        />
                        <Hint>{title.length}/200</Hint>
                    </Field>
                    <Field label={t("create.body")}>
                        <textarea
                            value={body}
                            onChange={(e) => setBody(e.target.value)}
                            placeholder={t("create.bodyPlaceholder")}
                            rows={8}
                        />
                        <Hint>
                            {fullTextBytes.length.toLocaleString()} bytes / 64 KiB
                        </Hint>
                    </Field>
                    <Field label={t("create.duration")}>
                        <div className="row">
                            {durationOptions.map((opt) => (
                                <label key={opt.key} className="radio">
                                    <input
                                        type="radio"
                                        name="duration"
                                        checked={durationKey === opt.key}
                                        onChange={() => setDurationKey(opt.key)}
                                    />
                                    <span>{opt.label}</span>
                                </label>
                            ))}
                        </div>
                    </Field>
                    <Field label={t("create.threshold")}>
                        <input
                            type="number"
                            min={1}
                            max={1_000_000}
                            value={threshold}
                            onChange={(e) =>
                                setThreshold(
                                    Math.max(
                                        1,
                                        Math.min(
                                            1_000_000,
                                            Number(e.target.value) || 1,
                                        ),
                                    ),
                                )
                            }
                        />
                    </Field>

                    <div className="deposit">
                        <div>
                            <div className="muted small">{t("create.deposit")}</div>
                            <div className="deposit__amount mono">
                                {depositErr
                                    ? "—"
                                    : deposit === null
                                      ? t("create.depositLoading")
                                      : `${formatEther(deposit)} ETH`}
                            </div>
                            <div className="muted small">
                                {t("create.depositRefund")}
                            </div>
                        </div>
                        <button
                            type="button"
                            className="btn btn--primary"
                            onClick={() => void onSubmit()}
                            disabled={!valid || deposit === null}
                        >
                            {session ? t("create.createBtn") : t("create.connectAndCreate")}
                        </button>
                    </div>

                    {errMsg ? (
                        <div className="notice notice--bad" style={{ marginTop: 16 }}>
                            <div>
                                <strong>{t("create.errorTitle")}</strong>
                                <br />
                                <span className="small mono">{errMsg}</span>
                            </div>
                        </div>
                    ) : null}
                </div>
            ) : stage === "connect" ? (
                <ConnectPanel
                    onConnected={async (s) => {
                        setSession(s);
                        await runSubmit(s);
                    }}
                    onCancel={() => setStage("form")}
                />
            ) : stage === "submitting" ? (
                <StatusPanel
                    title={t("create.signingTitle")}
                    body={t("create.signingBody")}
                />
            ) : stage === "mining" ? (
                <StatusPanel
                    title={t("create.miningTitle")}
                    body={t("create.miningBody")}
                    txHash={txHash}
                />
            ) : (
                <DonePanel
                    txHash={txHash!}
                    newId={newId}
                    onView={() => {
                        if (newId !== null) navigate(`/p/${newId.toString()}`);
                        else navigate("/petitions");
                    }}
                />
            )}
        </section>
    );
}

function Field({
    label,
    children,
}: {
    label: string;
    children: React.ReactNode;
}) {
    return (
        <div className="field">
            <label>{label}</label>
            {children}
        </div>
    );
}
function Hint({ children }: { children: React.ReactNode }) {
    return <div className="muted small" style={{ marginTop: 4 }}>{children}</div>;
}

function ConnectPanel({
    onConnected,
    onCancel,
}: {
    onConnected: (s: WalletSession) => Promise<void>;
    onCancel: () => void;
}) {
    const { t } = useTranslation();
    const [busy, setBusy] = useState<string | null>(null);
    const [err, setErr] = useState<string | null>(null);
    const injected = listInjectedProviders();

    const connect = async (which: "wc" | "injected", index?: number) => {
        setBusy(which === "wc" ? "wc" : `i-${index}`);
        setErr(null);
        try {
            const s =
                which === "wc"
                    ? await connectWalletConnect()
                    : await connectInjected(injected[index!]!);
            await onConnected(s);
        } catch (e) {
            setErr(e instanceof Error ? e.message : String(e));
            setBusy(null);
        }
    };

    return (
        <div className="card">
            <h3>{t("create.connectTitle")}</h3>
            <p className="muted small" style={{ marginTop: 8 }}>
                {t("create.connectBody")}
            </p>
            <div className="stack--4" style={{ marginTop: 16 }}>
                {injected.map((d, i) => (
                    <button
                        key={d.info.uuid}
                        type="button"
                        className="btn btn--ghost btn--block"
                        disabled={busy !== null}
                        onClick={() => void connect("injected", i)}
                    >
                        {busy === `i-${i}` ? t("create.opening") : d.info.name}
                    </button>
                ))}
                <button
                    type="button"
                    className="btn btn--ghost btn--block"
                    disabled={busy !== null}
                    onClick={() => void connect("wc")}
                >
                    {busy === "wc" ? t("create.opening") : "WalletConnect"}
                </button>
                <button
                    type="button"
                    className="btn btn--link"
                    onClick={onCancel}
                >
                    {t("common.cancel")}
                </button>
            </div>
            {err ? (
                <div className="notice notice--bad" style={{ marginTop: 16 }}>
                    <div className="small mono">{err}</div>
                </div>
            ) : null}
        </div>
    );
}

function StatusPanel({
    title,
    body,
    txHash,
}: {
    title: string;
    body: string;
    txHash?: `0x${string}` | null;
}) {
    return (
        <div className="card">
            <h3>{title}</h3>
            <p className="muted small" style={{ marginTop: 8 }}>{body}</p>
            {txHash ? (
                <p style={{ marginTop: 12 }}>
                    <a
                        href={`${config.blockExplorerUrl}/tx/${txHash}`}
                        target="_blank"
                        rel="noreferrer"
                        className="small mono"
                    >
                        {txHash.slice(0, 10)}…{txHash.slice(-6)}
                    </a>
                </p>
            ) : null}
        </div>
    );
}

function DonePanel({
    txHash,
    newId,
    onView,
}: {
    txHash: `0x${string}`;
    newId: bigint | null;
    onView: () => void;
}) {
    const { t } = useTranslation();
    return (
        <div className="card">
            <div className="notice notice--ok">
                <div>
                    {t("create.doneOk", { id: newId !== null ? `#${newId.toString()}` : "" })}
                </div>
            </div>
            <p className="muted small" style={{ marginTop: 12 }}>
                {t("create.doneTx")}{" "}
                <a
                    href={`${config.blockExplorerUrl}/tx/${txHash}`}
                    target="_blank"
                    rel="noreferrer"
                    className="mono"
                >
                    {txHash.slice(0, 10)}…{txHash.slice(-6)}
                </a>
            </p>
            <button
                type="button"
                className="btn btn--primary btn--block"
                style={{ marginTop: 16 }}
                onClick={onView}
            >
                {newId !== null ? t("create.viewPoll") : t("create.backToPolls")}
            </button>
        </div>
    );
}
