import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
    parseP7s,
    computeNullifier,
    buildWitness,
    findIntermediate,
    type FoundIntermediate,
    type ParsedP7s,
} from "@crisp-qes/sdk";
import { DropZone } from "../components/DropZone";
import { Steps, type StepKey } from "../components/Steps";
import {
    bytesEqual,
    bytesToHex,
    expectedMessageDigest,
} from "../lib/messageDigest";
import { readPetition, readTrustRoot, type PetitionView } from "../lib/registry";
import { loadTrustManifest, type TrustManifest } from "../lib/manifest";
import { submitSignature, basescanTxUrl } from "../lib/relayer";
import { config } from "../config";

interface Props {
    petitionId: bigint;
    onBack: () => void;
    onDone: (txHash: `0x${string}`, newCount: number) => void;
}

type ProveStage =
    | "idle"
    | "initWorker"
    | "loadingCircuit"
    | "buildWitness"
    | "proving"
    | "done";

interface ProveOutput {
    proofBytes: Uint8Array;
    publicInputs: string[];
}

export function Sign({ petitionId, onBack, onDone }: Props) {
    const { t } = useTranslation();

    const [petition, setPetition] = useState<PetitionView | null>(null);
    const [petitionErr, setPetitionErr] = useState<string | null>(null);

    const [parsing, setParsing] = useState(false);
    const [parsed, setParsed] = useState<ParsedP7s | null>(null);
    const [parseErr, setParseErr] = useState<string | null>(null);
    const [tinuaOk, setTinuaOk] = useState<boolean | null>(null);
    const [digestOk, setDigestOk] = useState<boolean | null>(null);

    const [manifest, setManifest] = useState<TrustManifest | null>(null);
    const [manifestErr, setManifestErr] = useState<string | null>(null);
    const [bundleBytes, setBundleBytes] = useState<Uint8Array | null>(null);
    const [foundCa, setFoundCa] = useState<FoundIntermediate | null>(null);
    const [caMissing, setCaMissing] = useState(false);
    const [caChecking, setCaChecking] = useState(false);
    const [trustRoot, setTrustRoot] = useState<bigint | null>(null);

    const [nullifier, setNullifier] = useState<string | null>(null);

    const [proveStage, setProveStage] = useState<ProveStage>("idle");
    const [proveErr, setProveErr] = useState<string | null>(null);
    const [proof, setProof] = useState<ProveOutput | null>(null);

    const [submitting, setSubmitting] = useState(false);
    const [submitErr, setSubmitErr] = useState<string | null>(null);

    // Load petition + trust root + manifest + public Diia .p7b bundle in
    // parallel. The bundle is served as a static asset at /diia_ecdsa.p7b
    // and is the AKI-lookup fallback for .p7s files that omit the issuer.
    useEffect(() => {
        let alive = true;
        (async () => {
            try {
                const [p, tr, mf, bundle] = await Promise.all([
                    readPetition(petitionId),
                    readTrustRoot(),
                    loadTrustManifest().catch((e) => {
                        if (alive) setManifestErr(e instanceof Error ? e.message : String(e));
                        return null;
                    }),
                    fetch("/diia_ecdsa.p7b", { credentials: "omit" })
                        .then(async (r) =>
                            r.ok ? new Uint8Array(await r.arrayBuffer()) : null,
                        )
                        .catch(() => null),
                ]);
                if (!alive) return;
                if (!p) {
                    setPetitionErr("petition not found");
                    return;
                }
                setPetition(p);
                setTrustRoot(BigInt(tr));
                if (mf) setManifest(mf);
                if (bundle) setBundleBytes(bundle);
            } catch (e) {
                if (alive) setPetitionErr(e instanceof Error ? e.message : String(e));
            }
        })();
        return () => {
            alive = false;
        };
    }, [petitionId]);

    const trustOk = !!foundCa && !caMissing;

    const active: StepKey = useMemo<StepKey>(() => {
        if (!parsed) return "upload";
        if (tinuaOk === false || digestOk === false) return "verify";
        if (!trustOk) return "trust";
        if (!nullifier) return "nullifier";
        if (proveStage !== "done") return "prove";
        return "submit";
    }, [parsed, tinuaOk, digestOk, trustOk, nullifier, proveStage]);

    const done = useMemo<Set<StepKey>>(() => {
        const s = new Set<StepKey>();
        if (parsed) s.add("upload");
        if (tinuaOk && digestOk) s.add("verify");
        if (trustOk) s.add("trust");
        if (nullifier) s.add("nullifier");
        if (proveStage === "done") s.add("prove");
        return s;
    }, [parsed, tinuaOk, digestOk, trustOk, nullifier, proveStage]);

    async function onFile(file: File) {
        setParseErr(null);
        setTinuaOk(null);
        setDigestOk(null);
        setFoundCa(null);
        setCaMissing(false);
        setNullifier(null);
        setProof(null);
        setProveStage("idle");
        setParsing(true);
        try {
            const bytes = new Uint8Array(await file.arrayBuffer());
            const p = parseP7s(bytes);
            setParsed(p);

            // (a) TINUA prefix check.
            const prefix = new TextEncoder().encode("TINUA-");
            const okPrefix =
                p.subjectSerial.length >= prefix.length &&
                prefix.every((b, i) => p.subjectSerial[i] === b);
            setTinuaOk(okPrefix);

            // (b) messageDigest binding check.
            if (petition) {
                const want = expectedMessageDigest(petitionId, petition.textHash);
                setDigestOk(bytesEqual(want, p.messageDigest));
            }

            // (c) Nullifier preview — independent of trust check.
            const nul = await computeNullifier({
                pubkey: p.pubkey,
                petitionId,
            });
            setNullifier(nul);

            // (d) Trust-tree match: D-v2 trust root commits to intermediate CAs.
            //     `findIntermediate` recomputes the SPKI commit of the
            //     intermediate (from the .p7s bundle when present, or
            //     resolved via AKI against the public Diia .p7b fallback)
            //     and looks it up in the Diia manifest.
            if (manifest) {
                setCaChecking(true);
                try {
                    const found = await findIntermediate(p, manifest, {
                        bundleP7b: bundleBytes ?? undefined,
                    });
                    if (found) {
                        setFoundCa(found);
                    } else {
                        setCaMissing(true);
                    }
                } finally {
                    setCaChecking(false);
                }
            }
        } catch (e) {
            setParseErr(e instanceof Error ? e.message : String(e));
            setParsed(null);
        } finally {
            setParsing(false);
        }
    }

    async function startProve() {
        if (!parsed || !petition || !foundCa || trustRoot === null) return;
        setProveErr(null);
        setProveStage("initWorker");
        try {
            const witness = await buildWitness({
                parsed,
                petitionId,
                petitionTextHash: hexToBytes(petition.textHash),
                trustRoot,
                merklePath: foundCa.merklePath,
                merklePathIndices: foundCa.merklePathIndices,
                // When the .p7s omits the intermediate, the resolved
                // bundle cert overrides the (null) parsed.intermediate*.
                intermediate:
                    foundCa.source === "bundle"
                        ? {
                              spkiDer: foundCa.intermediateSpkiDer,
                              pubkey: foundCa.intermediatePubkey,
                              pubkeyOffset: foundCa.intermediatePubkeyOffset,
                          }
                        : undefined,
            });

            const worker = new Worker(
                new URL("../worker/prove.worker.ts", import.meta.url),
                { type: "module" },
            );

            await new Promise<void>((resolve, reject) => {
                worker.addEventListener("message", (ev: MessageEvent<unknown>) => {
                    const m = ev.data as
                        | { type: "stage"; stage: ProveStage }
                        | { type: "done"; proofBytes: number[]; publicInputs: string[] }
                        | { type: "error"; detail: string };
                    if (m.type === "stage") {
                        setProveStage(m.stage);
                    } else if (m.type === "done") {
                        setProof({
                            proofBytes: Uint8Array.from(m.proofBytes),
                            publicInputs: m.publicInputs,
                        });
                        setProveStage("done");
                        worker.terminate();
                        resolve();
                    } else {
                        worker.terminate();
                        reject(new Error(m.detail));
                    }
                });
                worker.addEventListener("error", (ev) => {
                    worker.terminate();
                    reject(new Error(ev.message || "worker error"));
                });
                worker.postMessage({
                    type: "prove",
                    witness: witness.inputs,
                    circuitUrl: config.circuitUrl,
                });
            });
        } catch (e) {
            setProveErr(e instanceof Error ? e.message : String(e));
            setProveStage("idle");
        }
    }

    async function doSubmit() {
        if (!parsed || !proof || !nullifier || !foundCa) return;
        setSubmitErr(null);
        setSubmitting(true);
        try {
            // Pubkey coordinates ride in the public-input array as 128-bit
            // limb pairs (slots 3-10, D-v2-fix); the contract reassembles
            // them before feeding the RIP-7212 precompile. We don't pass
            // them as standalone body fields anymore.
            const res = await submitSignature({
                petitionId,
                nullifier,
                leafSigR: bigIntTo32Hex(parsed.signature.r),
                leafSigS: bigIntTo32Hex(parsed.signature.s),
                intermediateSigR: bigIntTo32Hex(parsed.leafCertSignature.r),
                intermediateSigS: bigIntTo32Hex(parsed.leafCertSignature.s),
                proof: "0x" + bytesToHexRaw(proof.proofBytes),
                publicInputs: proof.publicInputs,
            });
            if (res.ok) {
                const newCount = petition ? petition.signatureCount + 1 : 0;
                onDone(res.txHash, newCount);
                return;
            }
            setSubmitErr(res.code);
        } catch (e) {
            setSubmitErr(e instanceof Error ? e.message : "Unknown");
        } finally {
            setSubmitting(false);
        }
    }

    return (
        <section className="section">
            <button className="btn--link" onClick={onBack} type="button">
                ← {t("sign.back")}
            </button>
            <h2 className="section__title" style={{ marginTop: 8 }}>
                {t("sign.heading", { id: petitionId.toString() })}
            </h2>

            {petitionErr ? <p className="error-line">{petitionErr}</p> : null}

            <Steps active={active} done={done} />

            {/* 1. Upload */}
            <div className="panel">
                <p className="panel__title">{t("sign.steps.upload")}</p>
                <DropZone onFile={onFile} busy={parsing} />
                {parseErr ? (
                    <p className="error-line">
                        {t("sign.upload.parseError", { detail: parseErr })}
                    </p>
                ) : null}
                {parsed ? <p className="tag-ok">{t("sign.upload.parsed")}</p> : null}
            </div>

            {/* 2. Verify */}
            {parsed ? (
                <div className="panel">
                    <p className="panel__title">{t("sign.steps.verify")}</p>
                    <dl>
                        <div className="field-row">
                            <dt>{t("sign.verify.subjectSerial")}</dt>
                            <dd>
                                <div className="mono">
                                    {new TextDecoder().decode(parsed.subjectSerial)}
                                </div>
                                {tinuaOk === true ? (
                                    <span className="tag-ok">
                                        ✓ {t("sign.verify.subjectSerialOk")}
                                    </span>
                                ) : tinuaOk === false ? (
                                    <span className="tag-bad">
                                        ✕ {t("sign.upload.wrongPrefix")}
                                    </span>
                                ) : null}
                            </dd>
                        </div>
                        <div className="field-row">
                            <dt>{t("sign.verify.messageDigest")}</dt>
                            <dd>
                                <div className="mono">{bytesToHex(parsed.messageDigest)}</div>
                                {digestOk === true ? (
                                    <span className="tag-ok">
                                        ✓ {t("sign.verify.messageDigestOk")}
                                    </span>
                                ) : digestOk === false ? (
                                    <span className="tag-bad">
                                        ✕ {t("sign.verify.messageDigestMismatch")}
                                    </span>
                                ) : null}
                            </dd>
                        </div>
                    </dl>
                </div>
            ) : null}

            {/* 3. Trust tree */}
            {parsed && tinuaOk && digestOk ? (
                <div className="panel">
                    <p className="panel__title">{t("sign.steps.trust")}</p>
                    {manifestErr ? (
                        <>
                            <p className="error-line">{t("sign.trust.manifestError")}</p>
                            <p className="note mono">{manifestErr}</p>
                        </>
                    ) : !manifest || caChecking ? (
                        <>
                            <p className="note">{t("sign.trust.loadingManifest")}</p>
                            <div className="progress__line">
                                <span />
                            </div>
                        </>
                    ) : foundCa ? (
                        <>
                            <p className="tag-ok">
                                ✓{" "}
                                {t(
                                    foundCa.source === "bundle"
                                        ? "sign.trust.intermediateFromBundle"
                                        : "sign.trust.intermediateOk",
                                    {
                                        name:
                                            foundCa.leaf.tspName ??
                                            foundCa.leaf.subjectDn ??
                                            "—",
                                        cn:
                                            foundCa.leaf.tspName ??
                                            foundCa.leaf.subjectDn ??
                                            "—",
                                    },
                                )}
                            </p>
                            <dl style={{ marginTop: 12 }}>
                                <div className="field-row">
                                    <dt>{t("sign.trust.subjectDn")}</dt>
                                    <dd className="mono">
                                        {foundCa.leaf.subjectDn ?? "—"}
                                    </dd>
                                </div>
                                <div className="field-row">
                                    <dt>{t("sign.trust.spkiCommit")}</dt>
                                    <dd className="mono">{foundCa.leaf.spkiCommit}</dd>
                                </div>
                            </dl>
                        </>
                    ) : parsed && parsed.intermediateCertDer === null ? (
                        <p className="tag-bad">✕ {t("sign.trust.intermediateUnknown")}</p>
                    ) : (
                        <p className="tag-bad">✕ {t("sign.trust.intermediateMissing")}</p>
                    )}
                </div>
            ) : null}

            {/* 4. Nullifier */}
            {nullifier ? (
                <div className="panel">
                    <p className="panel__title">{t("sign.steps.nullifier")}</p>
                    <p className="note">{t("sign.nullifier.explainer")}</p>
                    <dl style={{ marginTop: 16 }}>
                        <div className="field-row">
                            <dt>{t("sign.nullifier.label")}</dt>
                            <dd className="mono">{nullifier}</dd>
                        </div>
                    </dl>
                </div>
            ) : null}

            {/* 5. Prove */}
            {parsed && tinuaOk && digestOk && foundCa && nullifier ? (
                <div className="panel">
                    <p className="panel__title">{t("sign.steps.prove")}</p>
                    <p className="note">{t("sign.prove.intro")}</p>
                    {proveStage === "idle" ? (
                        <div className="actions">
                            <button
                                className="btn btn--accent"
                                onClick={startProve}
                                type="button"
                            >
                                {t("sign.prove.start")}
                            </button>
                        </div>
                    ) : proveStage === "done" ? (
                        <p className="tag-ok">✓ {t("sign.prove.stages.done")}</p>
                    ) : (
                        <div className="progress">
                            <span>{t(`sign.prove.stages.${proveStage}`)}</span>
                            <div className="progress__line">
                                <span />
                            </div>
                        </div>
                    )}
                    {proveErr ? (
                        <p className="error-line">
                            {t("sign.prove.error", { detail: proveErr })}
                        </p>
                    ) : null}
                </div>
            ) : null}

            {/* 6. Submit */}
            {proof ? (
                <div className="panel">
                    <p className="panel__title">{t("sign.steps.submit")}</p>
                    <p className="note">{t("sign.submit.intro")}</p>
                    <div className="actions">
                        <button
                            className="btn btn--accent"
                            onClick={doSubmit}
                            type="button"
                            disabled={submitting}
                        >
                            {submitting
                                ? t("sign.submit.sending")
                                : t("sign.submit.send")}
                        </button>
                    </div>
                    {submitErr ? (
                        <p className="error-line">
                            {t(`sign.submit.errors.${submitErr}`, {
                                defaultValue: t("sign.submit.errors.Unknown"),
                            })}
                        </p>
                    ) : null}
                </div>
            ) : null}
        </section>
    );
}

function bigIntTo32Hex(v: bigint): string {
    return "0x" + v.toString(16).padStart(64, "0");
}

function bytesToHexRaw(b: Uint8Array): string {
    return Array.from(b, (n) => n.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array {
    const s = hex.startsWith("0x") ? hex.slice(2) : hex;
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
    }
    return out;
}

// re-use basescan link helper; kept import side-effect-free.
void basescanTxUrl;
