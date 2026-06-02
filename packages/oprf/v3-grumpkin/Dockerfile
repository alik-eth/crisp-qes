# syntax=docker/dockerfile:1
#
# Container image for the v3 Grumpkin VOPRF node service (build, unaudited).
#
# This is the v3 analogue of packages/oprf/Dockerfile, but:
#   * it runs the standalone Fastify Grumpkin OPRF service (service/server.mjs),
#     NOT the live v2 ristretto service in packages/oprf/src/;
#   * proof-gating verifies enroll_commit_v2 UltraHonk proofs IN-PROCESS via
#     @aztec/bb.js — there is NO `bb`/barretenberg CLI in this image.
#
# Build context = packages/oprf/v3-grumpkin (this directory). The build needs:
#   * package.json + service/ + lib.mjs
#   * circuits/enroll_commit_v2/target/enroll_commit_v2.json  (the compiled ACIR
#     the proof gate loads). circuits/*/target/ is gitignored, so RUN
#     `nargo compile` in circuits/enroll_commit_v2 BEFORE building this image
#     (or build from a tree where that target JSON already exists).
#
# Base: node:22-bookworm-slim (glibc), amd64 (Fly fra). We run the bb.js Wasm
# backend, so the base libc does not actually matter for verification; slim just
# keeps the layer small and predictable.

# ── deps ──────────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package.json ./
# No committed lockfile for this standalone package; install from the manifest.
# --omit=dev: the service has no runtime devDependencies.
RUN npm install --omit=dev --no-audit --no-fund \
 && npm cache clean --force

# ── build: prune dead native backends + pre-bake the verifier CRS ─────────────
FROM deps AS build
WORKDIR /app
COPY lib.mjs ./lib.mjs
COPY service ./service
# threshold/ holds the Shamir/DKG-lite keygen that oprf-node.mjs (ShareNode +
# makeNodes) imports at startup — REQUIRED at runtime for the 2-of-3 threshold.
COPY threshold ./threshold
# enroll_commit_v2.json (compiled ACIR) is what the /v3/blind-eval gate loads at
# runtime (its vk derives from this bytecode in proof-gate.mjs). No test
# proof/public_inputs are copied for it: the enroll circuit needs a production
# Diia-CA witness that can't be reproduced at build time, so the CRS pre-bake
# smoke-tests the nullifier instead (same fixed-size verifier CRS).
COPY circuits/enroll_commit_v2/target/enroll_commit_v2.json \
     ./circuits/enroll_commit_v2/target/
# oprf_nullifier ACIR + its locally-reproducible test vector: /v3/register bakes
# its vk at startup, and the CRS pre-bake (bake-crs.mjs) runs one real verify of
# this proof to warm the SRS + smoke-test the in-process gate.
COPY circuits/oprf_nullifier/target/oprf_nullifier.json \
     circuits/oprf_nullifier/target/proof \
     circuits/oprf_nullifier/target/public_inputs \
     ./circuits/oprf_nullifier/target/

# bb.js bundles prebuilt NAPI backends for 4 platforms (~125MB). The native
# backend spawns a Unix-socket child that fails to start in this slim container,
# so we run the self-contained Wasm backend (BB_BACKEND=Wasm) and drop ALL the
# native builds — the bundled barretenberg-threads.wasm.gz is what we use.
RUN rm -rf node_modules/@aztec/bb.js/build

# Pre-bake the structured reference string the in-process UltraHonk verifier
# needs so the running container never reaches out to crs.aztec.network at
# request time. We bake it by running ONE real verify during the build against
# the committed circuit + its test proof; the verifier downloads the CRS it
# needs into CRS_PATH (the wasm vk-derivation path pulls the full ~64MB
# bn254_g1.dat + ~4MB grumpkin g1). The verify also doubles as a smoke test that
# the in-process gate works inside the image.
ENV CRS_PATH=/app/.bb-crs
RUN node service/bake-crs.mjs \
 && ls -la /app/.bb-crs \
 && test -f /app/.bb-crs/bn254_g1.dat

# ── runtime ───────────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
# Point bb.js at the CRS baked into the image so verify needs no network.
ENV CRS_PATH=/app/.bb-crs
# Self-contained wasm verifier (native NAPI backend fails to spawn in slim).
ENV BB_BACKEND=Wasm
# Single wasm thread keeps memory predictable on a small Fly VM.
ENV BB_THREADS=1

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/lib.mjs ./lib.mjs
COPY --from=build /app/service ./service
COPY --from=build /app/threshold ./threshold
# Runtime only needs the compiled ACIR; the test proof/public_inputs stay in the
# build stage (used solely to pre-bake the CRS).
COPY --from=build /app/circuits/enroll_commit_v2/target/enroll_commit_v2.json \
     ./circuits/enroll_commit_v2/target/enroll_commit_v2.json
COPY --from=build /app/circuits/oprf_nullifier/target/oprf_nullifier.json \
     ./circuits/oprf_nullifier/target/oprf_nullifier.json
COPY --from=build /app/.bb-crs ./.bb-crs

# PORT is supplied by fly.toml/env; server.mjs reads process.env.PORT and binds
# 0.0.0.0 under NODE_ENV=production. GRUMPKIN_OPRF_KEY is REQUIRED in production
# and must be supplied as a Fly secret (32-byte hex), never baked in.
EXPOSE 8788
CMD ["node", "service/server.mjs"]
