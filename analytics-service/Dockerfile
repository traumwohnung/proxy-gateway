FROM oven/bun:1 AS build
WORKDIR /app
COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile || bun install
COPY . .
RUN bun run build:web

FROM oven/bun:1
WORKDIR /app
COPY --from=build /app /app
ENV NODE_ENV=production
ENV ANALYTICS_DB_URL=file:/data/analytics.db
ENV INGEST_PORT=50051
ENV DASHBOARD_PORT=4321
ENV DASHBOARD_HOST=0.0.0.0
EXPOSE 50051 4321
VOLUME ["/data"]
CMD ["sh", "-c", "bun run src/db/migrate.ts && bun run src/server/index.ts"]
