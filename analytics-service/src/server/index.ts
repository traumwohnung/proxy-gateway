import http from 'node:http';
import http2 from 'node:http2';
import type { ConnectRouter } from '@connectrpc/connect';
import { connectNodeAdapter } from '@connectrpc/connect-node';
import { registerIngest } from './ingest.js';
import { handleAPI } from './rest.js';

const INGEST_PORT = Number(process.env.INGEST_PORT ?? 50051);
const DASHBOARD_PORT = Number(process.env.DASHBOARD_PORT ?? 4321);
const DASHBOARD_HOST = process.env.DASHBOARD_HOST ?? '127.0.0.1';

// ----- Ingest gRPC server (h2c, separate listener) -----
// h2c (HTTP/2 cleartext) so a standard Go grpc.Dial client can speak plain
// gRPC. Connect's gRPC protocol requires HTTP/2.
const ingestHandler = connectNodeAdapter({
  routes: (router: ConnectRouter) => registerIngest(router),
});
http2.createServer(ingestHandler).listen(INGEST_PORT, () => {
  console.log(`[ingest] listening on :${INGEST_PORT} (h2c)`);
});

// ----- Astro dashboard (separate listener, private bind) -----
// Astro's node middleware adapter only handles SSR HTML — static assets
// under dist/client/ (CSS, hydration JS) must be served separately.
async function startDashboard(): Promise<void> {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const url = await import('node:url');

  const here = path.dirname(url.fileURLToPath(import.meta.url));
  const clientDir = path.resolve(here, '../../dist/client');
  const entryPath = path.resolve(here, '../../dist/server/entry.mjs');

  if (!fs.existsSync(entryPath)) {
    console.log('[dashboard] not built — run `bun run build:web` to enable. Ingest still running.');
    return;
  }

  const mod = await import(url.pathToFileURL(entryPath).href);
  const ssrHandler = (mod as { handler: http.RequestListener }).handler;

  const mimeTypes: Record<string, string> = {
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.mjs': 'application/javascript; charset=utf-8',
    '.map': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
  };

  function serveStatic(req: http.IncomingMessage, res: http.ServerResponse): boolean {
    const reqUrl = req.url ?? '/';
    if (req.method !== 'GET' && req.method !== 'HEAD') return false;
    // Strip query string.
    const pathname = reqUrl.split('?')[0] ?? '/';
    // Block traversal.
    if (pathname.includes('..')) return false;
    const filePath = path.join(clientDir, pathname);
    if (!filePath.startsWith(clientDir)) return false;
    // Annotate as ReturnType so biome doesn't see implicit any. The
    // `fs.Stats` namespace doesn't survive a dynamic `import('node:fs')`
    // under TS 6, so derive the type from the function instead.
    let stat: ReturnType<typeof fs.statSync>;
    try {
      stat = fs.statSync(filePath);
    } catch {
      return false;
    }
    if (!stat.isFile()) return false;
    const ext = path.extname(filePath).toLowerCase();
    res.setHeader('Content-Type', mimeTypes[ext] ?? 'application/octet-stream');
    res.setHeader('Content-Length', stat.size);
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    if (req.method === 'HEAD') {
      res.end();
      return true;
    }
    fs.createReadStream(filePath).pipe(res);
    return true;
  }

  http
    .createServer(async (req, res) => {
      if (req.url?.startsWith('/api/')) {
        try {
          if (await handleAPI(req, res)) return;
        } catch (e) {
          res.statusCode = 500;
          res.end(JSON.stringify({ error: (e as Error).message }));
          return;
        }
      }
      if (serveStatic(req, res)) return;
      ssrHandler(req, res);
    })
    .listen(DASHBOARD_PORT, DASHBOARD_HOST, () => {
      console.log(`[dashboard] listening on ${DASHBOARD_HOST}:${DASHBOARD_PORT}`);
    });
}
await startDashboard();
