// Keep the in-memory Merkle store in lock-step with the on-chain
// EnrollmentRegistry. The store is a pure function of the ordered leaf set, so
// we rebuild it from the registry's CommitmentInserted(leafIndex, commitment)
// events and FAIL CLOSED unless the rebuilt root equals the on-chain
// enrollmentRoot(). Used (a) at service boot and (b) before each /v3/register
// when the on-chain root has moved — so restarts, failed relays, and any
// divergence self-heal to on-chain truth before we sign an updateRoot.
//
// Build/unaudited.

import { createPublicClient, http, parseAbiItem, getAddress } from "viem";
import { MerkleIndex, bigintToHex32 } from "./merkle.mjs";

const EV_COMMITMENT_INSERTED = parseAbiItem(
    "event CommitmentInserted(uint256 indexed leafIndex, bytes32 indexed commitment)",
);
const FN_ROOT = parseAbiItem("function enrollmentRoot() view returns (bytes32)");
const FN_LEAFCOUNT = parseAbiItem("function leafCount() view returns (uint256)");

// RPCs cap getLogs by block-range / result count; scan in windows.
const WINDOW = 9000n;

function client(rpcUrl) {
    return createPublicClient({ transport: http(rpcUrl) });
}

/** Cheap: the current on-chain root (for "do we need to re-sync?" checks). */
export async function readOnchainRoot({ rpcUrl, registry }) {
    return client(rpcUrl).readContract({
        address: getAddress(registry),
        abi: [FN_ROOT],
        functionName: "enrollmentRoot",
    });
}

/** Rebuild the Merkle store from chain; throw unless it matches on-chain root. */
export async function syncMerkleFromChain({ rpcUrl, registry, fromBlock }) {
    const c = client(rpcUrl);
    const reg = getAddress(registry);
    const [onchainRoot, leafCount, latest] = await Promise.all([
        c.readContract({ address: reg, abi: [FN_ROOT], functionName: "enrollmentRoot" }),
        c.readContract({ address: reg, abi: [FN_LEAFCOUNT], functionName: "leafCount" }),
        c.getBlockNumber(),
    ]);
    const n = Number(leafCount);

    const byIndex = new Map();
    for (let start = BigInt(fromBlock); start <= latest; start += WINDOW + 1n) {
        const end = start + WINDOW > latest ? latest : start + WINDOW;
        const logs = await c.getLogs({
            address: reg,
            event: EV_COMMITMENT_INSERTED,
            fromBlock: start,
            toBlock: end,
        });
        for (const l of logs) byIndex.set(Number(l.args.leafIndex), l.args.commitment);
    }

    // MerkleIndex stores/hashes leaves as bigints (toBE32 does bigint math).
    const leaves = [];
    for (let i = 0; i < n; i++) {
        const cmt = byIndex.get(i);
        if (!cmt) {
            throw new Error(
                `chain-sync: missing CommitmentInserted for leafIndex ${i} ` +
                    `(found ${byIndex.size}/${n}); widen REGISTRY_FROM_BLOCK`,
            );
        }
        leaves.push(BigInt(cmt));
    }

    const index = await MerkleIndex.fromLeaves(leaves);
    const rebuiltRoot = bigintToHex32(index.root);
    if (rebuiltRoot.toLowerCase() !== String(onchainRoot).toLowerCase()) {
        throw new Error(
            `chain-sync: rebuilt root ${rebuiltRoot} != on-chain ${onchainRoot} ` +
                `(leafCount=${n}) — refusing to sign against a wrong tree`,
        );
    }
    return { index, leaves, onchainRoot, leafCount: n };
}
