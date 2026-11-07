# syntax=docker/dockerfile:1

# Both stages MUST use the same base image tag: native modules (better-sqlite3,
# ssh2's optional cpu-features) are compiled here and copied into the runtime
# stage as-is, so the Node ABI and glibc must match. Keep the two FROM lines
# identical (Dependabot bumps them together). The tag is pinned by digest so a
# rebuild is reproducible; Dependabot moves the digest.

# --- build stage ---
FROM node:22-bookworm-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d AS build
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
# better-sqlite3 bundles prebuilds for every OS/arch (~17 MB); keep only the one
# it resolves for this platform (none if it compiled from source), then prove
# it still loads so a bad strip fails the build rather than the container.
RUN npm prune --omit=dev \
  && keep="$(node -p "require('./node_modules/better-sqlite3/lib/binding.js').getPrebuildPath()")" \
  && find /app/node_modules/better-sqlite3/prebuilds -name '*.node' ! -path "$keep" -delete \
  && node -e "require('better-sqlite3')(':memory:').prepare('select 1').get()"

# --- runtime stage ---
FROM node:22-bookworm-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d AS runtime
WORKDIR /app
ENV NODE_ENV=production

# The Bitwarden CLI (`bw`) is required by the Vaultwarden secrets client. It
# installs from its own lock file (docker/bw-cli/, whose overrides pin patched
# transitive dependencies) into /opt/bw-cli, kept out of the app's node_modules.
# openssh-client provides ssh-keygen, used by the vault_generate_ssh_key tool.
# openssl generates the self-signed LAN TLS certificate (src/web/tls.ts).
# Nothing runs npm, npx, corepack or yarn after this step, so they are removed:
# the base image ships them, and their bundled dependencies would otherwise sit
# in every scan of the runtime image.
COPY docker/bw-cli/package.json docker/bw-cli/package-lock.json /opt/bw-cli/
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates openssh-client openssl \
  && rm -rf /var/lib/apt/lists/* \
  && npm ci --prefix /opt/bw-cli --omit=dev \
  && ln -s /opt/bw-cli/node_modules/.bin/bw /usr/local/bin/bw \
  && bw --version \
  && npm cache clean --force \
  && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
    /opt/yarn-v* /usr/local/bin/yarn /usr/local/bin/yarnpkg /root/.npm

# No npm install here: there is no toolchain in this stage, so production deps
# come pre-built from the build stage.
COPY --from=build /app/package.json /app/package-lock.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY docker/healthcheck.mjs ./healthcheck.mjs

# All mutable state lives here and is mounted as a volume.
ENV SKELETON_KEY_DATA_DIR=/data
ENV SKELETON_KEY_PORT=8787
ENV SKELETON_KEY_BIND_HOST=0.0.0.0
RUN mkdir -p /data && chown -R node:node /data
VOLUME ["/data"]
USER node

EXPOSE 8787
# Liveness probe of /healthz; see docker/healthcheck.mjs for the scheme fallback
# and how it verifies the server's own certificate.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["node", "healthcheck.mjs"]

CMD ["node", "dist/server.js"]
