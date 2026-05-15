import { sqliteTable, integer, text, index } from 'drizzle-orm/sqlite-core';

export const usage = sqliteTable(
  'usage',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    // Wall-clock unix seconds at connection close.
    ts: integer('ts').notNull(),
    proxyset: text('proxyset').notNull(),
    // Canonical JSON of the session parameters (formerly affinity).
    sessionParams: text('session_params').notNull().default('{}'),
    sessionDurationMinutes: integer('session_duration_minutes').notNull().default(0),
    uploadBytes: integer('upload_bytes').notNull().default(0),
    downloadBytes: integer('download_bytes').notNull().default(0),
  },
  (t) => ({
    tsIdx: index('usage_ts_idx').on(t.ts),
    proxysetTsIdx: index('usage_proxyset_ts_idx').on(t.proxyset, t.ts),
  }),
);

export type UsageRow = typeof usage.$inferSelect;
export type UsageInsert = typeof usage.$inferInsert;
