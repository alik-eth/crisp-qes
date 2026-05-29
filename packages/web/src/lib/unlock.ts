// Unlock the local vault: WebAuthn PRF → AES-GCM → decrypt the
// IndexedDB enrollment row → cache in session memory.
//
// Subsequent calls in the same tab return the cached vault without
// re-prompting the Passkey. Used by both the inline Sign flow on
// PetitionDetail and the "show my signatures" affordance on /me.

import { evaluatePrfWithCredential } from "./webauthnPrf.js";
import {
    listEnrollments,
    unwrapPayload,
    hex as encHex,
} from "./encryptedStore.js";
import {
    getSessionPrf,
    setSessionPrf,
    getSessionVault,
    setSessionVault,
    type SessionVault,
} from "./passkeySession.js";

export async function unlockVault(): Promise<SessionVault> {
    const cached = getSessionVault();
    if (cached) return cached;

    const list = await listEnrollments();
    if (list.length === 0) {
        throw new Error("No enrollment on this device. Use Recover.");
    }
    const rec = list[list.length - 1]!;

    let prf = getSessionPrf();
    if (!prf) {
        const credId = encHex.fromHex(rec.credentialId);
        prf = await evaluatePrfWithCredential(credId);
        setSessionPrf(prf);
    }
    const payload = await unwrapPayload(rec.ciphertext, prf);

    const v: SessionVault = {
        enrollmentSecret: payload.enrollmentSecret,
        merklePath: payload.merklePath,
        merklePathIndices: payload.merklePathIndices.map((b) =>
            b === 0 || b === 1 ? b : 0,
        ),
        leafIndex: rec.leafIndex,
        credentialId: rec.credentialId,
    };
    setSessionVault(v);
    return v;
}
