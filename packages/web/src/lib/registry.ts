// Read paths against PetitionRegistry.

import { type Hex, hexToBytes } from "viem";
import { petitionRegistryAbi, PetitionStatusLabel, type PetitionStatusCode } from "./abi";
import { publicClient } from "./chain";
import { config } from "../config";

export interface PetitionView {
    id: bigint;
    creator: `0x${string}`;
    createdAt: bigint;
    deadline: bigint;
    threshold: number;
    signatureCount: number;
    thresholdReached: boolean;
    depositRefunded: boolean;
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

export async function readNextPetitionId(): Promise<bigint> {
    return publicClient.readContract({
        address: config.registry,
        abi: petitionRegistryAbi,
        functionName: "nextPetitionId",
    });
}

export async function readTrustRoot(): Promise<Hex> {
    return publicClient.readContract({
        address: config.registry,
        abi: petitionRegistryAbi,
        functionName: "trustRoot",
    });
}

export async function readPetition(id: bigint): Promise<PetitionView | null> {
    try {
        const [pet, status] = await Promise.all([
            publicClient.readContract({
                address: config.registry,
                abi: petitionRegistryAbi,
                functionName: "getPetition",
                args: [id],
            }),
            publicClient.readContract({
                address: config.registry,
                abi: petitionRegistryAbi,
                functionName: "petitionStatus",
                args: [id],
            }),
        ]);
        return {
            id,
            creator: pet.creator,
            createdAt: pet.createdAt,
            deadline: pet.deadline,
            threshold: Number(pet.threshold),
            signatureCount: Number(pet.signatureCount),
            thresholdReached: pet.thresholdReached,
            depositRefunded: pet.depositRefunded,
            textHash: pet.textHash,
            fullText: decodeText(pet.fullText),
            status: PetitionStatusLabel[Number(status) as PetitionStatusCode] ?? "Unknown",
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
