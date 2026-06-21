# ── Stage 1: Dependencies ────────────────────────────────────────────────────
FROM node:20-bookworm-slim AS deps
WORKDIR /app
# Install with a clean, reproducible tree. package-lock.json is generated on the
# first `npm install`; copy it when present for deterministic installs.
COPY package.json package-lock.json* ./
RUN npm ci || npm install

# ── Stage 2: Build ───────────────────────────────────────────────────────────
FROM node:20-bookworm-slim AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

# ── Stage 3: Runtime ─────────────────────────────────────────────────────────
# next.config.js sets output:'standalone', so .next/standalone contains a
# minimal node server with only the deps it actually needs — no full node_modules.
FROM node:20-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# Listen on all interfaces *inside* the container; exposure is constrained by the
# compose service (host networking bound to loopback). Overridable via env.
ENV HOSTNAME=0.0.0.0
ENV PORT=3000

# Run as the unprivileged 'node' user that ships with the base image.
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public

USER node
EXPOSE 3000
CMD ["node", "server.js"]
