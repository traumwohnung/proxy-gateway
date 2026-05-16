import { createHash } from 'node:crypto';
import { create } from '@bufbuild/protobuf';
import type { ConnectRouter, HandlerContext } from '@connectrpc/connect';
import { Code, ConnectError } from '@connectrpc/connect';
import { sql } from '../db/client.js';
import {
  type ConnectionClosed,
  type DropReport,
  type EpochTransition,
  type Event,
  Ingest,
  RecordAckSchema,
} from './gen/ingest/v1/ingest_pb.js';

const INGEST_TOKEN = process.env.INGEST_TOKEN ?? '';

// Each event = one raw_events row + one projection row. We accumulate per
// kind so each flush emits one multi-row INSERT per table inside a single
// transaction.
const BATCH_MAX_EVENTS = 500;
const BATCH_MAX_MS = 250;

// hash16 = first 16 bytes of SHA-256 over a canonical JSON string,
// lowercase hex (32 chars). Same function for session_params and
// session_meta — they live in separate dim tables but share hash semantics.
// Computing server-side keeps the wire payload self-describing.
function hash16(canonicalJson: string): string {
  if (!canonicalJson || canonicalJson === '{}') return '';
  return createHash('sha256').update(canonicalJson).digest('hex').slice(0, 32);
}

interface RawRow {
  eventId: string;
  ts: number;
  kind: string;
  payload: string;
  ingestedAt: number;
}
interface ConnRow {
  eventId: string;
  ts: number;
  connectionId: string;
  proxyset: string;
  provider: string;
  sessionHash: string;
  // meta_hash joins session_meta_dim. Empty string ("") means "no meta
  // supplied"; the dim has no corresponding row in that case.
  metaHash: string;
  epoch: number;
  sessionDurationMinutes: number;
  upstreamIp: string;
  sni: string;
  closeReason: string;
  uploadBytes: bigint;
  downloadBytes: bigint;
  durationMs: bigint;
}
interface EpochRow {
  sessionHash: string;
  epoch: number;
  upstreamIp: string;
  proxyset: string;
  provider: string;
  startedAt: number;
  startReason: string;
  eventId: string;
}
interface DimUpsert {
  hash: string;
  ts: number;
  // Empty string means "no canonical JSON on this event"; translated to NULL
  // server-side so the upsert preserves any existing value (see upsertDim).
  json: string;
}

interface Batch {
  raw: RawRow[];
  conns: ConnRow[];
  epochs: EpochRow[];
  paramsDims: DimUpsert[];
  metaDims: DimUpsert[];
}

function newBatch(): Batch {
  return { raw: [], conns: [], epochs: [], paramsDims: [], metaDims: [] };
}

function checkAuth(ctx: HandlerContext): void {
  if (!INGEST_TOKEN) return;
  const auth = ctx.requestHeader.get('authorization') ?? '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (token !== INGEST_TOKEN) {
    throw new ConnectError('invalid ingest token', Code.Unauthenticated);
  }
}

function canonicalConnectionClosed(c: ConnectionClosed, sHash: string, mHash: string): string {
  return JSON.stringify({
    connection_id: c.connectionId,
    proxyset: c.proxyset,
    provider: c.provider,
    session_hash: sHash,
    session_params: c.sessionParams,
    meta_hash: mHash,
    session_meta: c.sessionMeta || null,
    session_duration_minutes: c.sessionDurationMinutes,
    epoch: c.epoch,
    upstream_ip: c.upstreamIp,
    sni: c.sni,
    close_reason: c.closeReason,
    upload_bytes: c.uploadBytes.toString(),
    download_bytes: c.downloadBytes.toString(),
    duration_ms: c.durationMs.toString(),
  });
}

function canonicalEpochTransition(e: EpochTransition, hash: string): string {
  return JSON.stringify({
    session_hash: hash,
    session_params: e.sessionParams,
    proxyset: e.proxyset,
    provider: e.provider,
    prev_epoch: e.prevEpoch,
    new_epoch: e.newEpoch,
    prev_ip: e.prevIp,
    new_ip: e.newIp,
    start_reason: e.startReason,
  });
}

function canonicalDropReport(d: DropReport): string {
  return JSON.stringify({
    dropped_events: d.droppedEvents.toString(),
    window_start: d.windowStart ? Number(d.windowStart.seconds) : 0,
    window_end: d.windowEnd ? Number(d.windowEnd.seconds) : 0,
  });
}

function accept(batch: Batch, event: Event): void {
  const ts = event.ts ? Number(event.ts.seconds) : Math.floor(Date.now() / 1000);
  const ingestedAt = Math.floor(Date.now() / 1000);
  if (!event.eventId) return;

  const p = event.payload;
  switch (p.case) {
    case 'connectionClosed': {
      const c = p.value;
      const sHash = hash16(c.sessionParams);
      const mHash = hash16(c.sessionMeta);
      batch.raw.push({
        eventId: event.eventId,
        ts,
        kind: 'connection_closed',
        payload: canonicalConnectionClosed(c, sHash, mHash),
        ingestedAt,
      });
      batch.conns.push({
        eventId: event.eventId,
        ts,
        connectionId: c.connectionId,
        proxyset: c.proxyset,
        provider: c.provider,
        sessionHash: sHash,
        metaHash: mHash,
        epoch: c.epoch,
        sessionDurationMinutes: c.sessionDurationMinutes,
        upstreamIp: c.upstreamIp,
        sni: c.sni,
        closeReason: c.closeReason || 'ok',
        uploadBytes: c.uploadBytes,
        downloadBytes: c.downloadBytes,
        durationMs: c.durationMs,
      });
      if (sHash) batch.paramsDims.push({ hash: sHash, ts, json: c.sessionParams });
      if (mHash) batch.metaDims.push({ hash: mHash, ts, json: c.sessionMeta });
      return;
    }
    case 'epochTransition': {
      const e = p.value;
      const sHash = hash16(e.sessionParams);
      batch.raw.push({
        eventId: event.eventId,
        ts,
        kind: 'epoch_transition',
        payload: canonicalEpochTransition(e, sHash),
        ingestedAt,
      });
      batch.epochs.push({
        sessionHash: sHash,
        epoch: e.newEpoch,
        upstreamIp: e.newIp,
        proxyset: e.proxyset,
        provider: e.provider,
        startedAt: ts,
        startReason: e.startReason,
        eventId: event.eventId,
      });
      if (sHash) batch.paramsDims.push({ hash: sHash, ts, json: e.sessionParams });
      return;
    }
    case 'dropReport': {
      const d = p.value;
      batch.raw.push({
        eventId: event.eventId,
        ts,
        kind: 'drop_report',
        payload: canonicalDropReport(d),
        ingestedAt,
      });
      return;
    }
    case 'mitmRequest': {
      batch.raw.push({
        eventId: event.eventId,
        ts,
        kind: 'mitm_request',
        payload: '{}',
        ingestedAt,
      });
      return;
    }
    default:
      return;
  }
}

// ---------------------------------------------------------------------------
// Per-kind inserters. waddler's sql.values() emits one multi-row INSERT with
// proper parameter binding; ON CONFLICT clauses follow as plain SQL.
// ---------------------------------------------------------------------------

async function insertRaw(rows: RawRow[]): Promise<void> {
  if (rows.length === 0) return;
  const vals = sql.values(rows.map((r) => [r.eventId, r.ts, r.kind, r.payload, r.ingestedAt]));
  await sql`
    INSERT INTO raw_events (event_id, ts, kind, payload, ingested_at)
    VALUES ${vals}
    ON CONFLICT (event_id) DO NOTHING
  `;
}

async function insertConns(rows: ConnRow[]): Promise<void> {
  if (rows.length === 0) return;
  const vals = sql.values(
    rows.map((r) => [
      r.eventId,
      r.ts,
      r.connectionId,
      r.proxyset,
      r.provider,
      r.sessionHash,
      r.metaHash,
      r.epoch,
      r.sessionDurationMinutes,
      r.upstreamIp,
      r.sni,
      r.closeReason,
      r.uploadBytes,
      r.downloadBytes,
      r.durationMs,
    ]),
  );
  await sql`
    INSERT INTO connection_closed
      (event_id, ts, connection_id, proxyset, provider, session_hash, meta_hash, epoch,
       session_duration_minutes, upstream_ip, sni, close_reason,
       upload_bytes, download_bytes, duration_ms)
    VALUES ${vals}
    ON CONFLICT (event_id) DO NOTHING
  `;
}

async function insertEpochs(rows: EpochRow[]): Promise<void> {
  if (rows.length === 0) return;
  const vals = sql.values(
    rows.map((r) => [
      r.sessionHash,
      r.epoch,
      r.upstreamIp,
      r.proxyset,
      r.provider,
      r.startedAt,
      r.startReason,
      r.eventId,
    ]),
  );
  await sql`
    INSERT INTO session_epoch
      (session_hash, epoch, upstream_ip, proxyset, provider, started_at, start_reason, event_id)
    VALUES ${vals}
    ON CONFLICT (session_hash, epoch) DO NOTHING
  `;
}

async function upsertParamsDim(rows: DimUpsert[]): Promise<void> {
  if (rows.length === 0) return;
  const vals = sql.values(
    rows.map((r) => [r.hash, r.json === '' || r.json === '{}' ? null : r.json, r.ts, r.ts]),
  );
  // params_json: first-non-null wins (session identity is immutable per hash).
  await sql`
    INSERT INTO session_params_dim (hash, params_json, first_seen, last_seen)
    VALUES ${vals}
    ON CONFLICT (hash) DO UPDATE SET
      params_json = CASE WHEN session_params_dim.params_json IS NULL THEN EXCLUDED.params_json ELSE session_params_dim.params_json END,
      last_seen   = GREATEST(session_params_dim.last_seen, EXCLUDED.last_seen)
  `;
}

async function upsertMetaDim(rows: DimUpsert[]): Promise<void> {
  if (rows.length === 0) return;
  const vals = sql.values(
    rows.map((r) => [r.hash, r.json === '' || r.json === '{}' ? null : r.json, r.ts, r.ts]),
  );
  // meta_json: first-non-null wins, same semantics as params_dim. The dim
  // is keyed by a content hash of the meta payload, so observing the same
  // hash twice means we already have its JSON.
  await sql`
    INSERT INTO session_meta_dim (hash, meta_json, first_seen, last_seen)
    VALUES ${vals}
    ON CONFLICT (hash) DO UPDATE SET
      meta_json = CASE WHEN session_meta_dim.meta_json IS NULL THEN EXCLUDED.meta_json ELSE session_meta_dim.meta_json END,
      last_seen = GREATEST(session_meta_dim.last_seen, EXCLUDED.last_seen)
  `;
}

async function flush(batch: Batch): Promise<void> {
  if (batch.raw.length === 0) return;

  // One transaction per flush. raw_events is the commit point; on failure the
  // whole batch rolls back and the gateway retries via at-least-once
  // redelivery (event_id idempotency makes retries safe).
  await sql`BEGIN TRANSACTION`;
  try {
    await insertRaw(batch.raw);
    await upsertParamsDim(batch.paramsDims);
    await upsertMetaDim(batch.metaDims);
    await insertConns(batch.conns);
    await insertEpochs(batch.epochs);
    await sql`COMMIT`;
  } catch (err) {
    await sql`ROLLBACK`.execute().catch(() => undefined);
    throw err;
  }

  batch.raw.length = 0;
  batch.conns.length = 0;
  batch.epochs.length = 0;
  batch.paramsDims.length = 0;
  batch.metaDims.length = 0;
}

export function registerIngest(router: ConnectRouter): void {
  router.service(Ingest, {
    async recordEvents(stream: AsyncIterable<Event>, ctx: HandlerContext) {
      checkAuth(ctx);

      const batch = newBatch();
      let lastFlush = Date.now();
      let accepted = 0n;

      try {
        for await (const event of stream) {
          accept(batch, event);
          accepted += 1n;
          if (batch.raw.length >= BATCH_MAX_EVENTS || Date.now() - lastFlush >= BATCH_MAX_MS) {
            await flush(batch);
            lastFlush = Date.now();
          }
        }
        await flush(batch);
      } catch (err) {
        await flush(batch).catch(() => {});
        throw err;
      }
      return create(RecordAckSchema, { accepted });
    },
  });
}
