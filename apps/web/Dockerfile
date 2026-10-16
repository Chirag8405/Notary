# Build context: repository root (see docker-compose.yml)
FROM node:24-slim AS build
RUN npm install -g pnpm@12.13.0
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile
# The browser talks to the server directly, so this URL must be reachable from the host.
ARG NEXT_PUBLIC_NOTARY_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_NOTARY_API_URL=$NEXT_PUBLIC_NOTARY_API_URL
# Generated schema/client files are committed, so no Python is needed to build the web app.
RUN pnpm --filter @notary/web exec next build

FROM node:24-slim
WORKDIR /app
ENV NODE_ENV=production PORT=3000 HOSTNAME=0.0.0.0
COPY --from=build /app/apps/web/.next/standalone ./
COPY --from=build /app/apps/web/.next/static ./apps/web/.next/static
EXPOSE 3000
CMD ["node", "apps/web/server.js"]
