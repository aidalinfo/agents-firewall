# syntax=docker/dockerfile:1
# agents-firewall console — Nuxt 4 SPA served by Nitro (node-server).
# Build: docker build -t agents-firewall-console console/
# Run:   docker run -p 3000:3000 -e NUXT_PUBLIC_API_MODE=http -e NUXT_PUBLIC_API_BASE=https://afw.example agents-firewall-console

FROM node:24-bookworm-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=cache,id=pnpm,target=/pnpm-store \
    pnpm config set store-dir /pnpm-store && \
    pnpm install --frozen-lockfile --ignore-scripts
COPY . .
RUN pnpm nuxt prepare && pnpm build

FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    NUXT_PUBLIC_API_MODE=http \
    NUXT_PUBLIC_API_BASE=""
WORKDIR /app
COPY --from=build --chown=node:node /app/.output ./.output
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", ".output/server/index.mjs"]
