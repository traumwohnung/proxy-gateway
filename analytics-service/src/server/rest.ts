import type http from 'node:http';
import { runUsageQuery, validate } from '../db/query.js';

function readBody(req: http.IncomingMessage, limit = 256 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > limit) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    // Cast to satisfy TS 6 / @types/node: Buffer is now generic over its
    // backing ArrayBuffer kind and Buffer.concat's parameter type forbids
    // SharedArrayBuffer. We only push regular Buffers, so the cast is safe.
    req.on('end', () => resolve(Buffer.concat(chunks as readonly Uint8Array[]).toString('utf8')));
    req.on('error', reject);
  });
}

function writeJSON(res: http.ServerResponse, status: number, body: unknown): void {
  const buf = Buffer.from(JSON.stringify(body));
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', buf.length);
  res.end(buf);
}

// handleAPI returns true when it served the request; false to let the caller
// fall through to the next handler.
export async function handleAPI(
  req: http.IncomingMessage,
  res: http.ServerResponse,
): Promise<boolean> {
  const url = req.url ?? '';
  if (!url.startsWith('/api/')) return false;

  if (url === '/api/usage/query' || url.startsWith('/api/usage/query?')) {
    if (req.method !== 'POST') {
      writeJSON(res, 405, { error: 'method not allowed' });
      return true;
    }
    let body: unknown;
    try {
      const raw = await readBody(req);
      body = raw.length ? JSON.parse(raw) : {};
    } catch (e) {
      writeJSON(res, 400, { error: 'invalid JSON body', detail: (e as Error).message });
      return true;
    }
    const v = validate(body);
    if (!v.ok) {
      writeJSON(res, 400, { errors: v.errors });
      return true;
    }
    try {
      const result = await runUsageQuery(v.query);
      writeJSON(res, 200, result);
    } catch (e) {
      writeJSON(res, 500, { error: 'query failed', detail: (e as Error).message });
    }
    return true;
  }

  writeJSON(res, 404, { error: 'not found' });
  return true;
}
