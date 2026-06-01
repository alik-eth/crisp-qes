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
ENV VITE_CHAIN_ID=$VITE_CHAIN_ID \
    VITE_RPC_URL=$VITE_RPC_URL \
    VITE_OPRF_URL=$VITE_OPRF_URL \
    VITE_ENROLLMENT_REGISTRY=$VITE_ENROLLMENT_REGISTRY \
    VITE_PETITION_REGISTRY_V2=$VITE_PETITION_REGISTRY_V2 \
    VITE_RELAYER_URL=$VITE_RELAYER_URL \
    VITE_CIRCUIT_URL=$VITE_CIRCUIT_URL \
    VITE_BLOCK_EXPLORER=$VITE_BLOCK_EXPLORER \
    VITE_WALLETCONNECT_PROJECT_ID=$VITE_WALLETCONNECT_PROJECT_ID \
    VITE_OPRF_PUBKEY=$VITE_OPRF_PUBKEY

COPY packages/sdk packages/sdk
COPY packages/web packages/web

RUN pnpm --filter @crisp-qes/sdk build
RUN pnpm --filter @crisp-qes/web build

# Mirror the Barretenberg CRS into the build output so we serve it same-origin
# from /crs/ instead of crs.aztec.network (whose TLS cert expired 2026-06,
# breaking all in-browser proving). bb.js range-fetches g1.dat (BN254, up to
# 2^20 points = 64 MiB for the enroll circuit), grumpkin_g1.dat (Grumpkin,
# 2^16+1 points), and the tiny g2.dat. -k bypasses the expired cert at build
# time; the browser never touches the bad host. See src/worker/crsRedirect.ts.
RUN apk add --no-cache curl \
 && mkdir -p packages/web/dist/crs \
 && curl -fkSL -o packages/web/dist/crs/g2.dat 'https://crs.aztec.network/g2.dat' \
 && curl -fkSL -r 0-67108927 -o packages/web/dist/crs/g1.dat 'https://crs.aztec.network/g1.dat' \
 && curl -fkSL -r 0-8388607 -o packages/web/dist/crs/grumpkin_g1.dat 'https://crs.aztec.network/grumpkin_g1.dat' \
 && ls -l packages/web/dist/crs

FROM caddy:2-alpine AS runtime
COPY --from=build /repo/packages/web/dist /srv
COPY packages/web/Caddyfile /etc/caddy/Caddyfile
EXPOSE 80
