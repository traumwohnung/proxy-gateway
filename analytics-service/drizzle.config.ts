import type { Config } from 'drizzle-kit';

export default {
  schema: './src/db/schema.ts',
  out: './src/db/migrations',
  dialect: 'turso',
  dbCredentials: {
    url: process.env.ANALYTICS_DB_URL ?? 'file:./analytics.db',
  },
} satisfies Config;
