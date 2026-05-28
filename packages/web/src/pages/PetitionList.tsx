import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
    BaseError,
    ContractFunctionRevertedError,
    getAddress,
} from "viem";
import { readAllPetitions, type PetitionView } from "../lib/registry";
import { useWallet } from "../lib/walletContext";
import { petitionRegistryAbi } from "../lib/abi";
import { config } from "../config";
import { ensureChain } from "../lib/wallet";

interface Props {
    onSign: (id: bigint) => void;
}

function shortAddr(addr: string): string {
    return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function formatDate(epochSecs: bigint, locale: string): string {
    return new Date(Number(epochSecs) * 1000).toLocaleString(locale, {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
    });
}

interface WithdrawState {
    [petitionIdStr: string]:
        | { kind: "idle" }
        | { kind: "submitting" }
        | { kind: "mining" }
        | { kind: "error"; message: string };
}

export function PetitionList({ onSign }: Props) {
    const { t, i18n } = useTranslation();
    const [items, setItems] = useState<PetitionView[] | null>(null);
    const [err, setErr] = useState<string | null>(null);
    const [now, setNow] = useState<number>(() => Math.floor(Date.now() / 1000));
    const { session, setSession } = useWallet();
    const [wd, setWd] = useState<WithdrawState>({});

    const reload = useCallback(async () => {
        try {
            const all = await readAllPetitions();
            setItems(all);
        } catch (e) {
            setErr(e instanceof Error ? e.message : String(e));
        }
    }, []);

    useEffect(() => {
        void reload();
        // Re-tick "now" once a minute so the "deadline passed" branch flips
        // without the user having to refresh.
        const id = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 60_000);
        return () => clearInterval(id);
    }, [reload]);

    async function handleWithdraw(p: PetitionView) {
        if (!session) return;
        const key = p.id.toString();
        try {
            if (session.chainId !== config.chainId) {
                const post = await ensureChain(session);
                setSession({ ...session, chainId: post });
                if (post !== config.chainId) {
                    setWd((s) => ({
                        ...s,
                        [key]: {
                            kind: "error",
                            message: t("list.card.withdraw.errors.wrongChain"),
                        },
                    }));
                    return;
                }
            }
            setWd((s) => ({ ...s, [key]: { kind: "submitting" } }));

            const { publicClient } = await import("../lib/chain");
            // Simulate on our public RPC for a proper gas estimate + early
            // revert decoding (otherwise MetaMask falls back to a too-low
            // default and the wallet sees an opaque revert).
            const { request } = await publicClient.simulateContract({
                account: session.address,
                address: config.registry,
                abi: petitionRegistryAbi,
                functionName: "withdrawDeposit",
                args: [p.id],
            });
            let gas = request.gas;
            if (!gas) {
                gas = await publicClient.estimateContractGas({
                    account: session.address,
                    address: config.registry,
                    abi: petitionRegistryAbi,
                    functionName: "withdrawDeposit",
                    args: [p.id],
                });
            }
            const gasBuf = (gas * 125n) / 100n;

            const txHash = await session.client.writeContract({
                ...request,
                gas: gasBuf,
                account: session.address,
                chain: config.chain,
            });
            setWd((s) => ({ ...s, [key]: { kind: "mining" } }));
            const receipt = await publicClient.waitForTransactionReceipt({
                hash: txHash,
            });
            if (receipt.status !== "success") {
                setWd((s) => ({
                    ...s,
                    [key]: {
                        kind: "error",
                        message: t("list.card.withdraw.errors.unknown"),
                    },
                }));
                return;
            }
            setWd((s) => ({ ...s, [key]: { kind: "idle" } }));
            await reload();
        } catch (e) {
            setWd((s) => ({
                ...s,
                [key]: {
                    kind: "error",
                    message: friendlyWithdrawError(e, t),
                },
            }));
        }
    }

    const connectedAddr = useMemo(
        () => (session ? getAddress(session.address) : null),
        [session],
    );

    if (err) {
        return (
            <section className="section">
                <h2 className="section__title">{t("list.heading")}</h2>
                <p className="error-line">{t("list.error")}</p>
                <p className="note mono">{err}</p>
            </section>
        );
    }

    if (items === null) {
        return (
            <section className="section">
                <h2 className="section__title">{t("list.heading")}</h2>
                <p className="note">{t("list.loading")}</p>
                <div className="progress__line">
                    <span />
                </div>
            </section>
        );
    }

    if (items.length === 0) {
        return (
            <section className="section">
                <h2 className="section__title">{t("list.heading")}</h2>
                <p className="note">{t("list.empty")}</p>
            </section>
        );
    }

    return (
        <section className="section">
            <p className="section__label">§ 03</p>
            <h2 className="section__title">{t("list.heading")}</h2>
            <div className="petition-grid">
                {items.map((p) => {
                    const ratio =
                        p.threshold > 0
                            ? Math.min(1, p.signatureCount / p.threshold)
                            : 0;
                    const statusClass =
                        p.status === "Open"
                            ? "status-tag--open"
                            : p.status === "ThresholdReached"
                              ? "status-tag--reached"
                              : "status-tag--closed";
                    const truncated =
                        p.fullText.length > 320
                            ? p.fullText.slice(0, 320) + "…"
                            : p.fullText;

                    const deadlinePassed = now > Number(p.deadline);
                    const isCreator =
                        connectedAddr !== null &&
                        getAddress(p.creator) === connectedAddr;
                    const canWithdraw =
                        isCreator && deadlinePassed && !p.depositRefunded;
                    const wdState = wd[p.id.toString()] ?? { kind: "idle" };

                    return (
                        <article className="petition-card" key={p.id.toString()}>
                            <div>
                                <p className="petition-card__id">
                                    {t("list.card.id", { id: p.id.toString() })}
                                </p>
                                <p className="petition-card__text">{truncated}</p>
                                <div className="petition-card__actions">
                                    <span className={`status-tag ${statusClass}`}>
                                        {t(`list.status.${p.status}`)}
                                    </span>
                                </div>
                            </div>
                            <dl className="petition-card__meta">
                                <div>
                                    <dt>{t("list.card.count")}</dt>
                                    <dd>
                                        <span className="petition-card__count">
                                            {p.signatureCount.toString()}
                                        </span>
                                        <span className="petition-card__count-of">
                                            {t("list.card.of")}{" "}
                                            {p.threshold.toString()}
                                        </span>
                                        <div className="petition-card__bar">
                                            <span
                                                style={{ width: `${ratio * 100}%` }}
                                            />
                                        </div>
                                    </dd>
                                </div>
                                <div>
                                    <dt>{t("list.card.deadline")}</dt>
                                    <dd>{formatDate(p.deadline, i18n.language)}</dd>
                                </div>
                                <div>
                                    <dt>{t("list.card.creator")}</dt>
                                    <dd className="mono">{shortAddr(p.creator)}</dd>
                                </div>
                                {p.status === "Open" ? (
                                    <div>
                                        <button
                                            className="btn btn--small"
                                            onClick={() => onSign(p.id)}
                                            type="button"
                                        >
                                            {t("list.card.sign")}
                                        </button>
                                    </div>
                                ) : (
                                    <div>
                                        {p.status === "ThresholdReached" ? (
                                            <p className="note">
                                                {t(
                                                    "list.card.closedReason.ThresholdReached",
                                                )}
                                            </p>
                                        ) : p.status === "Closed" ? (
                                            <p className="note">
                                                {t(
                                                    "list.card.closedReason.Closed",
                                                )}
                                            </p>
                                        ) : null}
                                    </div>
                                )}

                                {canWithdraw ? (
                                    <div>
                                        <button
                                            className="btn btn--small btn--ghost"
                                            type="button"
                                            onClick={() => handleWithdraw(p)}
                                            disabled={
                                                wdState.kind === "submitting" ||
                                                wdState.kind === "mining"
                                            }
                                        >
                                            {wdState.kind === "submitting"
                                                ? t(
                                                      "list.card.withdraw.submitting",
                                                  )
                                                : wdState.kind === "mining"
                                                  ? t(
                                                        "list.card.withdraw.mining",
                                                    )
                                                  : t("list.card.withdraw.cta")}
                                        </button>
                                        {wdState.kind === "error" ? (
                                            <p className="error-line">
                                                {wdState.message}
                                            </p>
                                        ) : null}
                                    </div>
                                ) : null}
                            </dl>
                        </article>
                    );
                })}
            </div>
        </section>
    );
}

function friendlyWithdrawError(
    err: unknown,
    t: (k: string) => string,
): string {
    if (err instanceof BaseError) {
        const reverted = err.walk(
            (e) => e instanceof ContractFunctionRevertedError,
        );
        if (reverted instanceof ContractFunctionRevertedError) {
            const name = reverted.data?.errorName;
            switch (name) {
                case "NotCreator":
                    return t("list.card.withdraw.errors.notCreator");
                case "PetitionStillOpen":
                    return t("list.card.withdraw.errors.stillOpen");
                case "DepositAlreadyRefunded":
                    return t("list.card.withdraw.errors.alreadyRefunded");
                case "RefundTransferFailed":
                    return t("list.card.withdraw.errors.transferFailed");
                default:
                    return reverted.shortMessage ?? t("list.card.withdraw.errors.unknown");
            }
        }
        return err.shortMessage ?? err.message;
    }
    if (err && typeof err === "object" && "code" in err) {
        const code = (err as { code?: number }).code;
        if (code === 4001) return t("list.card.withdraw.errors.userRejected");
    }
    return err instanceof Error ? err.message : String(err);
}
