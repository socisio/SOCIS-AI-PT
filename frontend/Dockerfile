FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# Remove the lockfile before install so npm RE-RESOLVES from package.json and
# honors its "overrides" (security bumps like sharp>=0.35.3 that Next pins to a
# vulnerable version). With the old lockfile present, npm install would keep the
# pinned vulnerable versions and silently ignore the overrides. npm writes a
# fresh, correct lockfile during the build.
RUN rm -f package-lock.json && npm install --legacy-peer-deps

# ─── Development stage ────────────────────────────────────────────────────────
# Used when NODE_ENV=development / target=dev in docker-compose.
# Source code is volume-mounted at runtime so hot reload works without rebuilds.
FROM node:20-alpine AS dev
WORKDIR /app
ENV NODE_ENV=development
ENV NEXT_TELEMETRY_DISABLED=1
# Copy deps from the deps stage; source is mounted via volume at runtime
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ARG NEXT_PUBLIC_API_URL=
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ARG NEXT_API_PROXY_URL=http://backend:8000
ENV NEXT_API_PROXY_URL=$NEXT_API_PROXY_URL
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"
CMD ["npm", "run", "dev"]
# Dev-stage healthcheck (dev stage intentionally runs as root for bind-mount
# ownership; production runner stage below uses the non-root nextjs user).
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD wget -qO- http://localhost:3000/ || exit 1

# Lists EVERY TypeScript error with the real compiler and real type definitions (build with: deploy/scripts/typecheck-frontend.sh).
FROM node:20-alpine AS typecheck
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npx tsc --noEmit

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
# Empty string = relative URLs → browser requests go to /api/... (same-origin)
# nginx then proxies /api/* to the backend, keeping cookies same-origin.
# Only override if the frontend and backend are on completely different domains.
ARG NEXT_PUBLIC_API_URL=
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
# Server-side proxy target: baked into routes-manifest.json at build time.
# Must be the Docker-network hostname of the backend container.
ARG NEXT_API_PROXY_URL=http://backend:8000
ENV NEXT_API_PROXY_URL=$NEXT_API_PROXY_URL
ARG NEXT_STRICT_BUILD=false
ENV NEXT_STRICT_BUILD=$NEXT_STRICT_BUILD
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"
# node:20-alpine ships busybox wget, so no extra package is needed.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:3000/ || exit 1

CMD ["node", "server.js"]
