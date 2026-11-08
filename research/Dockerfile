# Isolated runner for scanning third-party MCP servers. The server under test
# runs inside this container, never on the host. Probe only lists its tools.
FROM node:20-slim
WORKDIR /probe
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY assets ./assets
# Unprivileged user; npm cache and HOME live on the tmpfs mounted at /tmp.
USER node
ENV HOME=/tmp npm_config_cache=/tmp/npm npm_config_update_notifier=false
ENTRYPOINT ["node", "/probe/src/cli.mjs", "mcp", "--json", "--fail-on", "none", "--"]
