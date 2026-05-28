FROM node:22-alpine AS deps
WORKDIR /repo
RUN apk add --no-cache python3 make g++ \
 && corepack enable
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/sdk/package.json packages/sdk/package.json
COPY packages/lotl-flattener/package.json packages/lotl-flattener/package.json
COPY packages/v2-oprf/package.json packages/v2-oprf/package.json
RUN pnpm install --frozen-lockfile --filter "@crisp-qes/v2-oprf..."

FROM deps AS build
COPY packages/sdk packages/sdk
COPY packages/lotl-flattener packages/lotl-flattener
COPY packages/v2-oprf packages/v2-oprf
RUN pnpm --filter @crisp-qes/sdk build
RUN pnpm --filter @crisp-qes/lotl-flattener build
RUN pnpm --filter @crisp-qes/v2-oprf build
RUN pnpm --filter @crisp-qes/v2-oprf deploy --legacy --prod /out

FROM node:22-alpine AS runtime
WORKDIR /app
# better-sqlite3 ships a prebuilt .node binary inside node_modules; no extra
# native dep is needed at runtime on alpine-22.
COPY --from=build /out/dist ./dist
COPY --from=build /out/node_modules ./node_modules
COPY --from=build /out/package.json ./
ENV NODE_ENV=production
ENV DB_PATH=/data/oprf.db
EXPOSE 8788
CMD ["node", "dist/index.js"]
