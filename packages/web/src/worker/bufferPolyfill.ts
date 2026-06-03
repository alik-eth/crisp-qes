// The v3 vote SDK / @crisp-e3/zk-inputs use Node's `Buffer` global, which the
// browser worker realm doesn't define. Polyfill it before the SDK loads.
// Side-effect import — must come FIRST in voteProve.worker.ts.

/// <reference lib="webworker" />

import { Buffer } from "buffer";

const g = globalThis as unknown as { Buffer?: unknown };
if (!g.Buffer) g.Buffer = Buffer;

export {};
