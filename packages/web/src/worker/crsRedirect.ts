// bb.js downloads the Barretenberg CRS (g1.dat / g2.dat / grumpkin_g1.dat)
// from https://crs.aztec.network at proving time. As of 2026-06 that host's
// TLS certificate is EXPIRED, so browsers reject the connection and EVERY
// in-browser proof fails (`fetchG1Data` throws). We ship a same-origin mirror
// of the CRS under /crs/ (see packages/web/Dockerfile + Caddyfile) and redirect
// bb.js's fetch to it. Same-origin is also cleaner under our
// `Cross-Origin-Embedder-Policy: require-corp` than the cross-origin Aztec
// fetch (which would require CORP headers Aztec doesn't send).
//
// Imported purely for its side effect; load it before any proof is generated.

/// <reference lib="webworker" />

const CRS_ORIGIN = "https://crs.aztec.network";

const original = self.fetch.bind(self);

self.fetch = ((input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url =
        typeof input === "string"
            ? input
            : input instanceof URL
              ? input.href
              : input.url;
    if (url.startsWith(CRS_ORIGIN)) {
        // e.g. https://crs.aztec.network/g1.dat -> <origin>/crs/g1.dat
        const mirrored = self.location.origin + "/crs" + url.slice(CRS_ORIGIN.length);
        // Bypass the HTTP cache: if the CRS mirror 404s once (e.g. before it is
        // provisioned), browsers cache that failure and poison every later proof.
        // Always revalidate against the server.
        return original(mirrored, { ...init, cache: "reload" });
    }
    return original(input, init);
}) as typeof fetch;

export {};
