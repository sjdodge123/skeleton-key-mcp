# syntax=docker/dockerfile:1

# Both stages MUST use the same base image tag: native modules (better-sqlite3,
# ssh2's optional cpu-features) are compiled here and copied into the runtime
# stage as-is, so the Node ABI and glibc must match. Keep the two FROM lines
# identical (Dependabot bumps them together).

# --- build stage ---
FROM node:22-bookworm-slim AS build
WORKDIR /app
# Toolchain for node-gyp. better-sqlite3 always runs node-gyp at install (even
# when it ships a prebuild for the platform, configure needs Python), and
# cpu-features compiles from source. None of this reaches the runtime image.
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* ./
# Full install (incl. dev deps) so we can compile TypeScript.
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build
# Drop dev deps; the compiled native modules stay in place for the runtime stage.
RUN npm prune --omit=dev

# --- runtime stage ---
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production

# The Bitwarden CLI (`bw`) is required by the Vaultwarden secrets client.
# It is installed globally and kept out of the app's node_modules.
# openssh-client provides ssh-keygen, used by the vault_generate_ssh_key tool.
# openssl generates the self-signed LAN TLS certificate (src/web/tls.ts).
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates openssh-client openssl \
  && rm -rf /var/lib/apt/lists/* \
  && npm install -g @bitwarden/cli@2026.9.1 \
  && npm cache clean --force

# No npm install here: there is no toolchain in this stage, so production deps
# come pre-built from the build stage.
COPY --from=build /app/package.json /app/package-lock.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist

# All mutable state lives here and is mounted as a volume.
ENV SKELETON_KEY_DATA_DIR=/data
ENV SKELETON_KEY_PORT=8787
ENV SKELETON_KEY_BIND_HOST=0.0.0.0
RUN mkdir -p /data && chown -R node:node /data
VOLUME ["/data"]
USER node

EXPOSE 8787
# Probes the scheme implied by SKELETON_KEY_TLS; in auto mode it falls back to
# HTTP so the cert-generation-failure fallback still reports live (that
# degradation is deliberate — the boot log carries the warning). Disabling TLS
# verification is fine HERE only: it's a localhost liveness probe against our
# own self-signed cert, not a real client connection.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD NODE_TLS_REJECT_UNAUTHORIZED=0 node -e "const p=process.env.SKELETON_KEY_PORT||8787;const off=(process.env.SKELETON_KEY_TLS||'').trim().toLowerCase()==='off';const t=s=>fetch(s+'://127.0.0.1:'+p+'/healthz').then(r=>{if(!r.ok)throw new Error(s)});(off?t('http'):t('https').catch(()=>t('http'))).then(()=>process.exit(0),()=>process.exit(1))"

CMD ["node", "dist/server.js"]
