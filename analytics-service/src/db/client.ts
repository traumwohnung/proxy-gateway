import { createClient, type Client } from '@libsql/client';
import { drizzle } from 'drizzle-orm/libsql';
import * as schema from './schema.js';

const url = process.env.ANALYTICS_DB_URL ?? 'file:./analytics.db';
const authToken = process.env.ANALYTICS_DB_AUTH_TOKEN;

export const sqlite: Client = createClient({ url, authToken });
export const db = drizzle(sqlite, { schema });

// Enable WAL on local file databases (no-op on remote libSQL).
if (url.startsWith('file:')) {
  await sqlite.execute('PRAGMA journal_mode=WAL');
  await sqlite.execute('PRAGMA synchronous=NORMAL');
  await sqlite.execute('PRAGMA foreign_keys=ON');
}
