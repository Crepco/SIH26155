# ---------------------------------------------------------------------------
# Crucible frontend
#
# Standalone output so the runtime container installs nothing. Every asset,
# including fonts, is baked in at build time - see docs/11-air-gap.md.
# ---------------------------------------------------------------------------

FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci


FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# The build is not trusted, it is checked: a single external font or script
# reference makes the offline claim false, and it arrives silently with a
# copied component.
RUN npm run check:offline


FROM node:20-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

RUN addgroup -g 10001 -S crucible && adduser -u 10001 -S crucible -G crucible

COPY --from=builder --chown=crucible:crucible /app/.next/standalone ./
COPY --from=builder --chown=crucible:crucible /app/.next/static ./.next/static
COPY --from=builder --chown=crucible:crucible /app/public ./public

USER crucible
EXPOSE 3000

CMD ["node", "server.js"]
