import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ROOT_DIR, loadProfileConfig, loadPresetsConfig, loadSourcesConfig } from './ingest.mjs';
import { runPipeline } from './cli.mjs';
import {
  DATA_DIR,
  loadLatestDigest,
  listSavedDigests,
  loadChecklistState,
  saveChecklistState,
  renderMarkdownDigest
} from './store.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(ROOT_DIR, 'public');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.md': 'text/markdown; charset=utf-8'
};

let activeJob = null;

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

async function readBodyJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

export function startServer(port = Number(process.env.PORT || 3377)) {
  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      const p = url.pathname;

      // API routes
      if (p === '/api/digest' && req.method === 'GET') {
        const hours = url.searchParams.get('hours');
        const digest = await loadLatestDigest(hours ? Number(hours) : null);
        if (!digest) {
          return sendJson(res, 404, { error: 'No digest generated yet. Click Refresh Digest to run.' });
        }
        return sendJson(res, 200, digest);
      }

      if (p === '/api/digests' && req.method === 'GET') {
        const files = await listSavedDigests();
        return sendJson(res, 200, { files });
      }

      if (p === '/api/status' && req.method === 'GET') {
        return sendJson(res, 200, { activeJob });
      }

      if (p === '/api/refresh' && req.method === 'POST') {
        if (activeJob?.running) {
          return sendJson(res, 409, { error: 'A refresh job is already running.', activeJob });
        }
        const body = await readBodyJson(req);
        const hours = Math.max(1, Math.min(720, Number(body.hours || 168)));
        const engine = String(body.engine || 'auto');
        const maxIncidents = Math.max(5, Math.min(50, Number(body.maxIncidents || 28)));
        const roleOverride = body.roleTitle
          ? {
              roleId: body.roleId || 'custom',
              roleTitle: String(body.roleTitle).trim(),
              stackContext: String(body.stackContext || '').trim(),
              briefLabel: String(body.briefLabel || 'Industry Brief').trim()
            }
          : null;

        if (roleOverride) {
          const currentProfile = await loadProfileConfig();
          const mergedProfile = { ...currentProfile, ...roleOverride };
          await fs.mkdir(DATA_DIR, { recursive: true });
          await fs.writeFile(path.join(DATA_DIR, 'profile.local.json'), JSON.stringify(mergedProfile, null, 2), 'utf8');
        }

        activeJob = {
          running: true,
          hours,
          engine,
          startedAt: new Date().toISOString(),
          logs: [`Starting ${hours}h refresh (engine: ${engine})...`],
          error: null,
          completedAt: null
        };

        // Run asynchronously so UI can poll /api/status cleanly
        runPipeline({
          hours,
          engine,
          maxIncidents,
          roleOverride,
          onProgress: (msg) => {
            if (activeJob) activeJob.logs.push(msg);
          }
        })
          .then(({ digest }) => {
            if (activeJob) {
              activeJob.running = false;
              activeJob.completedAt = new Date().toISOString();
              activeJob.logs.push(`Done: ${digest.stats.incidentsAnalyzed} incidents analyzed.`);
            }
          })
          .catch((err) => {
            if (activeJob) {
              activeJob.running = false;
              activeJob.completedAt = new Date().toISOString();
              activeJob.error = err.message;
              activeJob.logs.push(`Error: ${err.message}`);
            }
          });

        return sendJson(res, 202, { started: true, activeJob });
      }

      if (p === '/api/state' && req.method === 'GET') {
        const state = await loadChecklistState();
        return sendJson(res, 200, state);
      }

      if (p === '/api/state' && req.method === 'POST') {
        const body = await readBodyJson(req);
        const current = await loadChecklistState();
        const merged = {
          checkedActions: { ...current.checkedActions, ...(body.checkedActions || {}) },
          dismissedIncidents: { ...current.dismissedIncidents, ...(body.dismissedIncidents || {}) }
        };
        const saved = await saveChecklistState(merged);
        return sendJson(res, 200, saved);
      }

      if (p === '/api/presets' && req.method === 'GET') {
        const presets = await loadPresetsConfig();
        return sendJson(res, 200, presets);
      }

      if (p === '/api/profile' && req.method === 'GET') {
        const profile = await loadProfileConfig();
        return sendJson(res, 200, profile);
      }

      if (p === '/api/profile' && req.method === 'PUT') {
        const body = await readBodyJson(req);
        await fs.mkdir(DATA_DIR, { recursive: true });
        const target = path.join(DATA_DIR, 'profile.local.json');
        await fs.writeFile(target, JSON.stringify(body, null, 2), 'utf8');
        return sendJson(res, 200, { saved: true, profile: body });
      }

      if (p === '/api/sources' && req.method === 'GET') {
        const cfg = await loadSourcesConfig();
        return sendJson(res, 200, cfg);
      }

      if (p === '/api/export/markdown' && req.method === 'GET') {
        const hours = url.searchParams.get('hours');
        const digest = await loadLatestDigest(hours ? Number(hours) : null);
        if (!digest) return sendJson(res, 404, { error: 'No digest available' });
        const md = renderMarkdownDigest(digest);
        const fname = `blastradius-${digest.hours}h-${digest.generatedAt.slice(0, 10)}.md`;
        res.writeHead(200, {
          'Content-Type': 'text/markdown; charset=utf-8',
          'Content-Disposition': `attachment; filename="${fname}"`
        });
        return res.end(md);
      }

      // Static files
      const rel = p === '/' ? 'index.html' : p.replace(/^\/+/, '');
      const fullPath = path.resolve(PUBLIC_DIR, rel);
      if (!fullPath.startsWith(PUBLIC_DIR)) {
        res.writeHead(403);
        return res.end('Forbidden');
      }
      const data = await fs.readFile(fullPath);
      const ext = path.extname(fullPath).toLowerCase();
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      res.end(data);
    } catch (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404);
        return res.end('Not found');
      }
      sendJson(res, 500, { error: err.message });
    }
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`[blastradius] Dashboard live at http://127.0.0.1:${port}`);
  });
  return server;
}

const isDirectRun = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
if (isDirectRun) {
  startServer();
}
