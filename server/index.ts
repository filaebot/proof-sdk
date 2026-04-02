import express from 'express';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import path from 'path';
import { fileURLToPath } from 'url';
import { apiRoutes } from './routes.js';
import { agentRoutes } from './agent-routes.js';
import { setupWebSocket } from './ws.js';
import { createBridgeMountRouter } from './bridge.js';
import { getCollabRuntime, startCollabRuntimeEmbedded } from './collab.js';
import { discoveryRoutes } from './discovery-routes.js';
import { shareWebRoutes } from './share-web-routes.js';
import {
  capabilitiesPayload,
  enforceApiClientCompatibility,
  enforceBridgeClientCompatibility,
} from './client-capabilities.js';
import { getBuildInfo } from './build-info.js';
import { metricsApiRoutes } from './metrics.js';
import { threadsAuthMiddleware, requireThreadsAuth, authenticateWsUpgrade } from './threads-auth.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number.parseInt(process.env.PORT || '4000', 10);
const DEFAULT_ALLOWED_CORS_ORIGINS = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:4000',
  'http://127.0.0.1:4000',
  'https://threads.filae.site',
  'https://proof.filae.site',
  'null',
];

function parseAllowedCorsOrigins(): Set<string> {
  const configured = (process.env.PROOF_CORS_ALLOW_ORIGINS || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  return new Set(configured.length > 0 ? configured : DEFAULT_ALLOWED_CORS_ORIGINS);
}

async function main(): Promise<void> {
  const app = express();
  const server = createServer(app);
  const wss = new WebSocketServer({ noServer: true });
  const allowedCorsOrigins = parseAllowedCorsOrigins();

  app.use(express.json({ limit: '10mb' }));

  // Serve built assets from dist/ (editor.js bundle) — no-cache for JS/CSS to avoid stale bundles
  app.use(express.static(path.join(__dirname, '..', 'dist'), {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('.js') || filePath.endsWith('.css')) {
        res.setHeader('Cache-Control', 'no-cache');
      }
    }
  }));
  app.use(express.static(path.join(__dirname, '..', 'public')));

  app.use((req, res, next) => {
    const originHeader = req.header('origin');
    if (originHeader && allowedCorsOrigins.has(originHeader)) {
      res.setHeader('Access-Control-Allow-Origin', originHeader);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Vary', 'Origin');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers',
      [
        'Content-Type',
        'Authorization',
        'X-Proof-Client-Version',
        'X-Proof-Client-Build',
        'X-Proof-Client-Protocol',
        'x-share-token',
        'x-bridge-token',
        'x-auth-poll-token',
        'X-Agent-Id',
        'X-Window-Id',
        'X-Document-Id',
        'Idempotency-Key',
        'X-Idempotency-Key',
      ].join(', '),
    );
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  app.get('/', (_req, res) => {
    res.type('html').send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Proof SDK</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; padding: 48px 24px; color: #17261d; background: #f7faf5; }
      main { max-width: 760px; margin: 0 auto; }
      h1 { font-size: 2.5rem; margin: 0 0 0.5rem; }
      p { font-size: 1.05rem; line-height: 1.6; }
      code { background: #eaf2e6; padding: 0.2rem 0.35rem; border-radius: 4px; }
      a { color: #266854; }
    </style>
  </head>
  <body>
    <main>
      <h1>Proof SDK</h1>
      <p>Open-source collaborative markdown editing with provenance tracking and an agent HTTP bridge.</p>
      <p>Start with <code>POST /documents</code>, inspect <a href="/agent-docs">agent docs</a>, or read <a href="/.well-known/agent.json">discovery metadata</a>.</p>
    </main>
  </body>
</html>`);
  });

  app.get('/health', (_req, res) => {
    const buildInfo = getBuildInfo();
    res.json({
      ok: true,
      buildInfo,
      collab: getCollabRuntime(),
    });
  });

  app.get('/api/capabilities', (_req, res) => {
    res.json(capabilitiesPayload());
  });

  app.use(discoveryRoutes);

  // Soft Threads auth — attaches req.threadsUser if credentials are present,
  // but does NOT reject unauthenticated requests. Individual routes decide
  // whether to require auth (share routes use their own share-token auth).
  app.use(threadsAuthMiddleware);

  // /api/metrics and /api/agent require hard Threads auth
  app.use('/api/metrics', requireThreadsAuth, metricsApiRoutes);
  app.use('/api/agent', requireThreadsAuth, agentRoutes);
  // Document API routes use slug-as-secret model (no hard auth gate) so the editor
  // SPA can call them from iframes where Threads session cookies aren't available.
  // The soft threadsAuthMiddleware (line 138) still attaches user info when present.
  app.use('/api', enforceApiClientCompatibility, apiRoutes);
  // Share web routes handle their own token-based auth — must be registered BEFORE
  // the requireThreadsAuth-gated /d and /documents mounts, otherwise app.use('/d', ...)
  // catches /d/:slug requests first and blocks them.
  app.use(shareWebRoutes);

  // Bridge and document routes use slug-as-secret auth model — no hard Threads auth gate.
  // The soft threadsAuthMiddleware (line 138) still attaches user info when available.
  app.use('/d', createBridgeMountRouter(enforceBridgeClientCompatibility));
  app.use('/documents', createBridgeMountRouter(enforceBridgeClientCompatibility));
  app.use('/documents', agentRoutes);

  setupWebSocket(wss);

  // Authenticate WebSocket upgrade requests before handing off to the WSS
  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url || '', `http://${req.headers.host}`);
    if (url.pathname !== '/ws') {
      socket.destroy();
      return;
    }

    // Attempt auth but allow connections through regardless — slug-as-secret model.
    // Authenticated users get richer capabilities; anonymous gets basic collab.
    authenticateWsUpgrade(req).then(() => {
      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit('connection', ws, req);
      });
    }).catch(() => {
      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit('connection', ws, req);
      });
    });
  });

  await startCollabRuntimeEmbedded(PORT);

  server.listen(PORT, () => {
    console.log(`[proof-sdk] listening on http://127.0.0.1:${PORT}`);
  });
}

main().catch((error) => {
  console.error('[proof-sdk] failed to start server', error);
  process.exit(1);
});
