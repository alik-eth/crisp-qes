FROM node:22-alpine AS deps
WORKDIR /repo
RUN corepack enable
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/relayer/package.json packages/relayer/package.json
RUN pnpm install --frozen-lockfile --filter "@crisp-qes/relayer..."

FROM deps AS build
COPY packages/relayer packages/relayer
RUN pnpm --filter @crisp-qes/relayer build
RUN pnpm --filter @crisp-qes/relayer deploy --legacy --prod /out

FROM node:22-alpine AS runtime
WORKDIR /app
COPY --from=build /out/dist ./dist
COPY --from=build /out/node_modules ./node_modules
COPY --from=build /out/package.json ./
ENV NODE_ENV=production
EXPOSE 8787
CMD ["node", "dist/index.js"]
