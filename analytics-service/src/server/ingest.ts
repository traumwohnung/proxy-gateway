import type { ConnectRouter, HandlerContext } from '@connectrpc/connect';
import { Code, ConnectError } from '@connectrpc/connect';
import { Ingest, type UsageDelta, RecordUsageAckSchema } from './gen/ingest/v1/ingest_pb.js';
import { create } from '@bufbuild/protobuf';
import { sqlite } from '../db/client.js';

const INGEST_TOKEN = process.env.INGEST_TOKEN ?? '';

// Each closed connection sends one UsageDelta. Batch a few hundred together
// so we don't hit SQLite once per connection.
const BATCH_MAX_ROWS = 500;
const BATCH_MAX_MS = 250;

interface Row {
  ts: number;
  proxyset: string;
  sessionParams: string;
  sessionDurationMinutes: number;
  uploadBytes: bigint;
  downloadBytes: bigint;
}

async function insertBatch(rows: Row[]): Promise<void> {
  if (rows.length === 0) return;
  const placeholders = rows.map(() => '(?, ?, ?, ?, ?, ?)').join(', ');
  const args: (string | number | bigint)[] = [];
  for (const r of rows) {
    args.push(r.ts, r.proxyset, r.sessionParams, r.sessionDurationMinutes, r.uploadBytes, r.downloadBytes);
  }
  const sql =
    `INSERT INTO usage (ts, proxyset, session_params, session_duration_minutes, upload_bytes, download_bytes) ` +
    `VALUES ${placeholders}`;
  await sqlite.execute({ sql, args });
}

function checkAuth(ctx: HandlerContext): void {
  if (!INGEST_TOKEN) return;
  const auth = ctx.requestHeader.get('authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (token !== INGEST_TOKEN) {
    throw new ConnectError('invalid ingest token', Code.Unauthenticated);
  }
}

export function registerIngest(router: ConnectRouter): void {
  router.service(Ingest, {
    async recordUsage(stream: AsyncIterable<UsageDelta>, ctx: HandlerContext) {
      checkAuth(ctx);

      let pending: Row[] = [];
      let lastFlush = Date.now();

      const flush = async () => {
        if (pending.length === 0) return;
        const batch = pending;
        pending = [];
        await insertBatch(batch);
        lastFlush = Date.now();
      };

      try {
        for await (const d of stream) {
          const ts = d.timestamp
            ? Number(d.timestamp.seconds)
            : Math.floor(Date.now() / 1000);
          pending.push({
            ts,
            proxyset: d.proxyset,
            sessionParams: d.sessionParams,
            sessionDurationMinutes: d.sessionDurationMinutes,
            uploadBytes: d.uploadBytes,
            downloadBytes: d.downloadBytes,
          });
          if (pending.length >= BATCH_MAX_ROWS || Date.now() - lastFlush >= BATCH_MAX_MS) {
            await flush();
          }
        }
        await flush();
      } catch (err) {
        await flush().catch(() => {});
        throw err;
      }
      return create(RecordUsageAckSchema, {});
    },
  });
}
