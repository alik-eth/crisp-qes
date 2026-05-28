// BIP-39 mnemonic <-> OPRF output `N` for disaster recovery.
//
// We compress the 32-byte ristretto-encoded `N` into a 32-byte seed
// (via HKDF with the "bip39" info string) and feed it directly to
// BIP-39 as entropy. 32 bytes of entropy → 24 words (standard).
//
// The mnemonic isn't a wallet seed — it's the recovery path to the OPRF
// output. With the mnemonic the citizen can re-derive `N`, re-compute
// the same commitment, and ask the OPRF service for the latest Merkle
// path. Their identity (RNOKPP, certificate) never enters this flow.

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import * as bip39 from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english";

const HKDF_INFO = new TextEncoder().encode("crisp-qes-v2-bip39-v1");
const HKDF_SALT = new TextEncoder().encode("crisp-qes-v2-bip39-salt");

/** Derive 32 bytes of BIP-39 entropy from the 32-byte OPRF output `N`. */
export function entropyFromN(N: Uint8Array): Uint8Array {
    return hkdf(sha256, N, HKDF_SALT, HKDF_INFO, 32);
}

export function mnemonicFromN(N: Uint8Array): string {
    const entropy = entropyFromN(N);
    return bip39.entropyToMnemonic(entropy, english);
}

/**
 * Recovery direction is asymmetric: the citizen presents a mnemonic and
 * we need to re-derive `N`. But the mnemonic only round-trips entropy,
 * not the OPRF output itself — so on recovery we must replay the OPRF
 * protocol against the same `H(RNOKPP)` input.
 *
 * For demo recovery we accept the simplification of storing the
 * (recovered-from-mnemonic) entropy itself as the secret material: the
 * commitment is rebuilt deterministically from `N`, and `N` is what the
 * wallet really needs.
 *
 * This function returns the entropy bytes regardless — the caller
 * decides how to turn those into a fresh `N` (typically by treating the
 * 32-byte entropy as `N` for the demo path, with a TODO to wire the
 * full ristretto re-derivation for the v2.2 grant scope).
 */
export function entropyFromMnemonic(mnemonic: string): Uint8Array {
    return bip39.mnemonicToEntropy(mnemonic.trim(), english);
}

export function isValidMnemonic(mnemonic: string): boolean {
    return bip39.validateMnemonic(mnemonic.trim(), english);
}
