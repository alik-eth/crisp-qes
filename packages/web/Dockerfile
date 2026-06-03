FROM node:22-alpine AS deps
WORKDIR /repo
RUN corepack enable
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/sdk/package.json packages/sdk/package.json
COPY packages/web/package.json packages/web/package.json
RUN pnpm install --frozen-lockfile --filter "@crisp-qes/web..."

FROM deps AS build
ARG VITE_CHAIN_ID
ARG VITE_RPC_URL
ARG VITE_OPRF_URL
ARG VITE_ENROLLMENT_REGISTRY
ARG VITE_PETITION_REGISTRY_V2
ARG VITE_RELAYER_URL
ARG VITE_CIRCUIT_URL
ARG VITE_BLOCK_EXPLORER
ARG VITE_WALLETCONNECT_PROJECT_ID
ARG VITE_OPRF_PUBKEY
ARG VITE_OPRF_ENROLLMENT_EPOCH
# CRISP FHE voting (operator chain + coordinator) — needed for the in-browser vote.
ARG VITE_FHE_OPERATOR_RPC
ARG VITE_FHE_COORDINATOR_URL
ARG VITE_FHE_BALLOT_REGISTRY
ARG VITE_FHE_CRISP_PROGRAM
ENV VITE_CHAIN_ID=$VITE_CHAIN_ID \
    VITE_RPC_URL=$VITE_RPC_URL \
    VITE_OPRF_URL=$VITE_OPRF_URL \
    VITE_ENROLLMENT_REGISTRY=$VITE_ENROLLMENT_REGISTRY \
    VITE_PETITION_REGISTRY_V2=$VITE_PETITION_REGISTRY_V2 \
    VITE_RELAYER_URL=$VITE_RELAYER_URL \
    VITE_CIRCUIT_URL=$VITE_CIRCUIT_URL \
    VITE_BLOCK_EXPLORER=$VITE_BLOCK_EXPLORER \
    VITE_WALLETCONNECT_PROJECT_ID=$VITE_WALLETCONNECT_PROJECT_ID \
    VITE_OPRF_PUBKEY=$VITE_OPRF_PUBKEY \
    VITE_OPRF_ENROLLMENT_EPOCH=$VITE_OPRF_ENROLLMENT_EPOCH \
    VITE_FHE_OPERATOR_RPC=$VITE_FHE_OPERATOR_RPC \
    VITE_FHE_COORDINATOR_URL=$VITE_FHE_COORDINATOR_URL \
    VITE_FHE_BALLOT_REGISTRY=$VITE_FHE_BALLOT_REGISTRY \
    VITE_FHE_CRISP_PROGRAM=$VITE_FHE_CRISP_PROGRAM

COPY packages/sdk packages/sdk
COPY packages/web packages/web

RUN pnpm --filter @crisp-qes/sdk build
# build:app = tsc + vite build only. The v3 vote worker (public/vote/) is built
# SEPARATELY (build:voteworker) against the vendored fork's v3 toolchain, which
# isn't in this image — it's pre-built on the host and COPY'd in via packages/web.
RUN pnpm --filter @crisp-qes/web build:app

# Mirror the Barretenberg CRS into the build output so we serve it same-origin
# from /crs/ instead of crs.aztec.network (whose TLS cert expired 2026-06,
# breaking all in-browser proving). bb.js range-fetches g1.dat (BN254),
# grumpkin_g1.dat (Grumpkin, 2^16+1 points), and the tiny g2.dat. We fetch 128
# MiB of g1 (2^21 points) — the in-browser VOTE proof is the ~1.5M-gate crisp_fold
# recursion (ADR-0001 path C), which needs more than the 64 MiB the enroll
# circuit alone used. -k bypasses the expired cert at build time; the browser
# never touches the bad host. See src/worker/crsRedirect.ts.
RUN apk add --no-cache curl \
 && mkdir -p packages/web/dist/crs \
 && curl -fkSL -o packages/web/dist/crs/g2.dat 'https://crs.aztec.network/g2.dat' \
 && curl -fkSL -r 0-134217727 -o packages/web/dist/crs/g1.dat 'https://crs.aztec.network/g1.dat' \
 && curl -fkSL -r 0-8388607 -o packages/web/dist/crs/grumpkin_g1.dat 'https://crs.aztec.network/grumpkin_g1.dat' \
 && ls -l packages/web/dist/crs

FROM caddy:2-alpine AS runtime
COPY --from=build /repo/packages/web/dist /srv
COPY packages/web/Caddyfile /etc/caddy/Caddyfile
EXPOSE 80
