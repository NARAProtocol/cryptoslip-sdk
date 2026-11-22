FROM node:22-alpine AS builder
WORKDIR /app

COPY packages/sdk/package.json packages/sdk/package-lock.json ./packages/sdk/
RUN npm ci --prefix packages/sdk --ignore-scripts
COPY packages/sdk ./packages/sdk
RUN npm run build --prefix packages/sdk && npm prune --prefix packages/sdk --omit=dev --ignore-scripts

COPY packages/mcp/package.json packages/mcp/package-lock.json ./packages/mcp/
RUN npm ci --prefix packages/mcp --ignore-scripts
COPY packages/mcp ./packages/mcp
RUN npm run build --prefix packages/mcp && npm prune --prefix packages/mcp --omit=dev --ignore-scripts

FROM node:22-alpine AS runtime
ENV NODE_ENV=production
ENV CRYPTOSLIP_STATE_PATH=/home/node/.cryptoslip-mcp/pocket-state.json
WORKDIR /app

COPY --from=builder --chown=node:node /app/packages ./packages
COPY --chown=node:node LICENSE README.md glama.json server.json smithery.yaml ./
RUN mkdir -p /home/node/.cryptoslip-mcp && chown -R node:node /home/node/.cryptoslip-mcp

VOLUME ["/home/node/.cryptoslip-mcp"]
USER node
ENTRYPOINT ["node", "/app/packages/mcp/dist/cli.js"]
