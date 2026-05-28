FROM node:22-alpine AS deps
WORKDIR /repo
RUN corepack enable
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/v2-relayer/package.json packages/v2-relayer/package.json
RUN pnpm install --frozen-lockfile --filter "@crisp-qes/v2-relayer..."

FROM deps AS build
COPY packages/v2-relayer packages/v2-relayer
RUN pnpm --filter @crisp-qes/v2-relayer build
RUN pnpm --filter @crisp-qes/v2-relayer deploy --legacy --prod /out

FROM node:22-alpine AS runtime
WORKDIR /app
COPY --from=build /out/dist ./dist
COPY --from=build /out/node_modules ./node_modules
COPY --from=build /out/package.json ./
ENV NODE_ENV=production
EXPOSE 8789
CMD ["node", "dist/index.js"]
