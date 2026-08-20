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
# openssh-client provides ssh-keygen, used by the vault_generate_ssh_key tool.
# openssl generates the self-signed LAN TLS certificate (src/web/tls.ts).
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates openssh-client openssl \
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
# Probes the scheme implied by SKELETON_KEY_TLS; in auto mode it falls back to
# HTTP so the cert-generation-failure fallback still reports live (that
# degradation is deliberate — the boot log carries the warning). Disabling TLS
# verification is fine HERE only: it's a localhost liveness probe against our
# own self-signed cert, not a real client connection.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD NODE_TLS_REJECT_UNAUTHORIZED=0 node -e "const p=process.env.SKELETON_KEY_PORT||8787;const off=(process.env.SKELETON_KEY_TLS||'').trim().toLowerCase()==='off';const t=s=>fetch(s+'://127.0.0.1:'+p+'/healthz').then(r=>{if(!r.ok)throw new Error(s)});(off?t('http'):t('https').catch(()=>t('http'))).then(()=>process.exit(0),()=>process.exit(1))"

CMD ["node", "dist/server.js"]
