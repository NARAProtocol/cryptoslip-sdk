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
WORKDIR /app

COPY --from=builder --chown=node:node /app/packages/sdk/package.json ./packages/sdk/package.json
COPY --from=builder --chown=node:node /app/packages/sdk/dist ./packages/sdk/dist
COPY --from=builder --chown=node:node /app/packages/sdk/node_modules ./packages/sdk/node_modules
COPY --from=builder --chown=node:node /app/packages/mcp/package.json ./packages/mcp/package.json
COPY --from=builder --chown=node:node /app/packages/mcp/dist ./packages/mcp/dist
COPY --from=builder --chown=node:node /app/packages/mcp/node_modules ./packages/mcp/node_modules
COPY --chown=node:node LICENSE ./LICENSE

USER node
ENTRYPOINT ["node", "/app/packages/mcp/dist/cli.js"]
