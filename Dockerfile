# syntax=docker/dockerfile:1

# --- build stage ---
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
# Full install (incl. dev deps) so we can compile TypeScript.
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# --- runtime stage ---
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production

# The Bitwarden CLI (`bw`) is required by the Vaultwarden secrets client.
# It is installed globally and kept out of the app's node_modules.
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && npm install -g @bitwarden/cli@2024.9.0 \
  && npm cache clean --force

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist

# All mutable state lives here and is mounted as a volume.
ENV SKELETON_KEY_DATA_DIR=/data
ENV SKELETON_KEY_PORT=8787
ENV SKELETON_KEY_BIND_HOST=0.0.0.0
RUN mkdir -p /data && chown -R node:node /data
VOLUME ["/data"]
USER node

EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.SKELETON_KEY_PORT||8787)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server.js"]
