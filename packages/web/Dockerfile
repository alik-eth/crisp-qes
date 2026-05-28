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
ARG VITE_REGISTRY_ADDRESS
ARG VITE_RELAYER_URL
ARG VITE_TRUST_MANIFEST_URL
ARG VITE_CIRCUIT_URL
ARG VITE_BLOCK_EXPLORER
ARG VITE_WALLETCONNECT_PROJECT_ID
ENV VITE_CHAIN_ID=$VITE_CHAIN_ID \
    VITE_RPC_URL=$VITE_RPC_URL \
    VITE_REGISTRY_ADDRESS=$VITE_REGISTRY_ADDRESS \
    VITE_RELAYER_URL=$VITE_RELAYER_URL \
    VITE_TRUST_MANIFEST_URL=$VITE_TRUST_MANIFEST_URL \
    VITE_CIRCUIT_URL=$VITE_CIRCUIT_URL \
    VITE_BLOCK_EXPLORER=$VITE_BLOCK_EXPLORER \
    VITE_WALLETCONNECT_PROJECT_ID=$VITE_WALLETCONNECT_PROJECT_ID

COPY packages/sdk packages/sdk
COPY packages/web packages/web

RUN pnpm --filter @crisp-qes/sdk build
RUN pnpm --filter @crisp-qes/web build

FROM caddy:2-alpine AS runtime
COPY --from=build /repo/packages/web/dist /srv
COPY packages/web/Caddyfile /etc/caddy/Caddyfile
EXPOSE 80
