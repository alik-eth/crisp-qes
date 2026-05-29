// Read paths against PetitionRegistryV2 + EnrollmentRegistry.
//
// Tuple shape of `getPetition` mirrors the deployed contract (#31):
//   { creator, createdAt, deadline, threshold, signatureCount,
//     thresholdReached, depositRefunded, mode,
//     yesCount, noCount, abstainCount, textHash, fullText }
//
// `signatureCount` is the Signature-mode tally; for YesNo / YesNoAbstain
// modes the totals come from yes+no(+abstain).

import { type Hex, hexToBytes } from "viem";
import {
    petitionRegistryV2Abi,
    enrollmentRegistryAbi,
    PetitionStatusLabel,
    type PetitionStatusCode,
    BallotModeLabel,
    type BallotMode,
} from "./abi";
import { publicClient } from "./chain";
import { config } from "../config";

export interface PetitionView {
    id: bigint;
    creator: `0x${string}`;
    createdAt: bigint;
    deadline: bigint;
    threshold: number;
    signatureCount: number;
    yesCount: number;
    noCount: number;
    abstainCount: number;
    thresholdReached: boolean;
    depositRefunded: boolean;
    mode: BallotMode;
    modeLabel: "Signature" | "YesNo" | "YesNoAbstain";
    textHash: Hex;
    fullText: string;
    status: "Open" | "Closed" | "ThresholdReached" | "Unknown";
}

function decodeText(bytes: Hex): string {
    try {
        return new TextDecoder("utf-8", { fatal: false }).decode(hexToBytes(bytes));
    } catch {
        return "";
    }
}

export async function readEnrollmentRoot(): Promise<Hex> {
    return publicClient.readContract({
        address: config.enrollmentRegistry,
        abi: enrollmentRegistryAbi,
        functionName: "enrollmentRoot",
    });
}

export async function readOprfAttester(): Promise<`0x${string}`> {
    return publicClient.readContract({
        address: config.enrollmentRegistry,
        abi: enrollmentRegistryAbi,
        functionName: "oprfAttester",
    });
}

export async function readHasNullifier(
    petitionId: bigint,
    nullifier: `0x${string}`,
): Promise<boolean> {
    return publicClient.readContract({
        address: config.petitionRegistryV2,
        abi: petitionRegistryV2Abi,
        functionName: "hasNullifier",
        args: [petitionId, nullifier],
    });
}

export async function readCreationDeposit(): Promise<bigint> {
    return publicClient.readContract({
        address: config.petitionRegistryV2,
        abi: petitionRegistryV2Abi,
        functionName: "CREATION_DEPOSIT",
    });
}

export async function readLeafCount(): Promise<bigint> {
    return publicClient.readContract({
        address: config.enrollmentRegistry,
        abi: enrollmentRegistryAbi,
        functionName: "leafCount",
    });
}

export async function readNextPetitionId(): Promise<bigint> {
    return publicClient.readContract({
        address: config.petitionRegistryV2,
        abi: petitionRegistryV2Abi,
        functionName: "nextPetitionId",
    });
}

export async function readPetition(id: bigint): Promise<PetitionView | null> {
    try {
        const [pet, status] = await Promise.all([
            publicClient.readContract({
                address: config.petitionRegistryV2,
                abi: petitionRegistryV2Abi,
                functionName: "getPetition",
                args: [id],
            }),
            publicClient.readContract({
                address: config.petitionRegistryV2,
                abi: petitionRegistryV2Abi,
                functionName: "petitionStatus",
                args: [id],
            }),
        ]);
        const mode = pet.mode as BallotMode;
        return {
            id,
            creator: pet.creator,
            createdAt: pet.createdAt,
            deadline: pet.deadline,
            threshold: Number(pet.threshold),
            signatureCount: Number(pet.signatureCount),
            yesCount: Number(pet.yesCount),
            noCount: Number(pet.noCount),
            abstainCount: Number(pet.abstainCount),
            thresholdReached: pet.thresholdReached,
            depositRefunded: pet.depositRefunded,
            mode,
            modeLabel: BallotModeLabel[mode],
            textHash: pet.textHash,
            fullText: decodeText(pet.fullText),
            status:
                PetitionStatusLabel[Number(status) as PetitionStatusCode] ??
                "Unknown",
        };
    } catch {
        return null;
    }
}

export async function readAllPetitions(): Promise<PetitionView[]> {
    const next = await readNextPetitionId();
    if (next <= 1n) return [];
    const ids: bigint[] = [];
    for (let i = 1n; i < next; i++) ids.push(i);
    const results = await Promise.all(ids.map(readPetition));
    return results.filter((p): p is PetitionView => p !== null);
}
