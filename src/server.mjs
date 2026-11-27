import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { ROOT_DIR, loadProfileConfig, loadPresetsConfig, loadSourcesConfig } from './ingest.mjs';
import { runPipeline } from './cli.mjs';
import { loadPlaybooks } from './playbooks.mjs';
import { AGENTS, listAgents, listHandoffs, createHandoff } from './handoff.mjs';
import {
  DATA_DIR, loadLatestDigest, listSavedDigests, loadChecklistState, saveChecklistState,
  renderMarkdownDigest, writeJsonAtomic
} from './store.mjs';

const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const MAX_BODY_BYTES = 64 * 1024;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.md': 'text/markdown; charset=utf-8'
};

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
};

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function sendJson(res, status, obj) {
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}

/**
 * The server listens on loopback only, but a browser on this machine can still be pointed at it by any
 * web page. Two checks close that:
 *  - Host must be this server's own loopback name. A DNS-rebinding page arrives with its own hostname.
 *  - Any request that changes state must carry our own Origin and a JSON content type. A cross-site form
 *    or no-cors fetch cannot send application/json without a preflight, which we never approve.
 */
export function checkRequest(req, port) {
  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  const host = String(req.headers.host || '').toLowerCase();
  if (!allowedHosts.has(host)) throw new HttpError(403, 'Forbidden: unexpected Host header');

  const origin = req.headers.origin;
  const allowedOrigins = new Set([...allowedHosts].map((h) => `http://${h}`));
  if (origin && !allowedOrigins.has(String(origin).toLowerCase())) throw new HttpError(403, 'Forbidden: cross-origin request');

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    if (!origin && req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin') {
      throw new HttpError(403, 'Forbidden: cross-site request');
    }
    const ct = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (ct !== 'application/json') throw new HttpError(415, 'Content-Type must be application/json');
  }
}

async function readBodyJson(req) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'Request body too large');
    chunks.push(c);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  let parsed;
  try { parsed = JSON.parse(raw); } catch { throw new HttpError(400, 'Body is not valid JSON'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new HttpError(400, 'Body must be a JSON object');
  return parsed;
}

const text = (v, max) => String(v ?? '').replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, max);

// Only known profile fields are stored, with length limits. This text ends up in the model prompt.
export function sanitizeProfile(input, base = {}) {
  const out = { ...base };
  if ('roleId' in input) out.roleId = text(input.roleId, 40) || 'custom';
  if ('roleTitle' in input) out.roleTitle = text(input.roleTitle, 120) || base.roleTitle || 'Cybersecurity Professional';
  if ('stackContext' in input) out.stackContext = text(input.stackContext, 600);
  if ('briefLabel' in input) out.briefLabel = text(input.briefLabel, 40) || 'Industry Brief';
  for (const listField of ['high_priority_keywords', 'products']) {
    if (Array.isArray(input[listField])) {
      out[listField] = input[listField].map((k) => text(k, 60)).filter(Boolean).slice(0, 100);
    }
  }
  return out;
}

const boolMap = (obj) =>
  Object.fromEntries(Object.entries(obj && typeof obj === 'object' ? obj : {}).slice(0, 500).map(([k, v]) => [text(k, 200), Boolean(v)]));

let activeJob = null;

export function startServer(port = Number(process.env.PORT || 3377)) {
  const server = http.createServer(async (req, res) => {
    try {
      const boundPort = server.address()?.port ?? port;
      checkRequest(req, boundPort);
      const url = new URL(req.url || '/', `http://127.0.0.1:${boundPort}`);
      const p = url.pathname;
      const hoursParam = url.searchParams.get('hours');

      if (p === '/api/digest' && req.method === 'GET') {
        const digest = await loadLatestDigest(hoursParam ? Number(hoursParam) : null);
        if (!digest) {
          return sendJson(res, 404, {
            error: hoursParam
              ? `No ${Number(hoursParam)}h digest yet. Click Refresh Digest to build one for this window.`
              : 'No digest generated yet. Click Refresh Digest to run.'
          });
        }
        return sendJson(res, 200, digest);
      }

      if (p === '/api/digests' && req.method === 'GET') {
        return sendJson(res, 200, { files: await listSavedDigests() });
      }

      if (p === '/api/status' && req.method === 'GET') {
        return sendJson(res, 200, { activeJob });
      }

      if (p === '/api/refresh' && req.method === 'POST') {
        if (activeJob?.running) return sendJson(res, 409, { error: 'A refresh job is already running.', activeJob });
        const body = await readBodyJson(req);
        const hours = Math.max(1, Math.min(720, Math.round(Number(body.hours) || 168)));
        const engine = ['auto', 'none', 'claude-cli', 'anthropic', 'gemini', 'openai'].includes(body.engine) ? body.engine : 'auto';
        const maxIncidents = Math.max(0, Math.min(300, Math.round(Number(body.maxIncidents) || 0)));

        let roleOverride = null;
        if (body.roleTitle) {
          const merged = sanitizeProfile(body, await loadProfileConfig());
          await writeJsonAtomic(path.join(DATA_DIR, 'profile.local.json'), merged);
          roleOverride = { roleId: merged.roleId, roleTitle: merged.roleTitle, stackContext: merged.stackContext, briefLabel: merged.briefLabel };
        }

        activeJob = {
          running: true, hours, engine, startedAt: new Date().toISOString(),
          logs: [`Starting ${hours}h refresh (engine: ${engine})...`], error: null, completedAt: null
        };
        const job = activeJob;

        runPipeline({ hours, engine, maxIncidents, roleOverride, onProgress: (msg) => { job.logs.push(msg); if (job.logs.length > 200) job.logs.shift(); } })
          .then(({ digest }) => {
            job.logs.push(`Done: ${digest.stats.incidentsAnalyzed} analysed, ${digest.stats.unanalyzed} not analysed.`);
          })
          .catch((err) => {
            job.error = err.message;
            job.logs.push(`Error: ${err.message}`);
          })
          .finally(() => {
            job.running = false;
            job.completedAt = new Date().toISOString();
          });

        return sendJson(res, 202, { started: true, activeJob });
      }

      if (p === '/api/state' && req.method === 'GET') {
        return sendJson(res, 200, await loadChecklistState());
      }

      if (p === '/api/state' && req.method === 'POST') {
        const body = await readBodyJson(req);
        const current = await loadChecklistState();
        const saved = await saveChecklistState({
          checkedActions: { ...current.checkedActions, ...boolMap(body.checkedActions) },
          dismissedIncidents: { ...current.dismissedIncidents, ...boolMap(body.dismissedIncidents) }
        });
        return sendJson(res, 200, saved);
      }

      // ----- Hand an incident to the person's own agent -----

      if (p === '/api/agents' && req.method === 'GET') {
        return sendJson(res, 200, { agents: await listAgents() });
      }

      if (p === '/api/handoffs' && req.method === 'GET') {
        return sendJson(res, 200, { handoffs: await listHandoffs() });
      }

      if (p === '/api/handoff' && req.method === 'POST') {
        const body = await readBodyJson(req);
        // The request names an incident and an agent from fixed lists. No text from the browser reaches the prompt or a command line.
        if (!AGENTS.some((a) => a.id === body.agent)) throw new HttpError(400, 'Unknown agent');
        const digest = await loadLatestDigest(Number(body.hours) || 168);
        const incident = digest?.incidents?.find((i) => i.id === body.incidentId);
        if (!incident) throw new HttpError(404, 'That incident is not in the current digest');
        if (incident.verdict === 'UNANALYZED') throw new HttpError(409, 'This incident has not been analysed, so there is nothing to hand over yet');
        const out = await createHandoff({ incident, playbooks: await loadPlaybooks(), agentId: body.agent, launch: body.launch === true });
        return sendJson(res, 201, {
          id: out.id, prompt: out.prompt, promptPath: out.promptPath, launched: out.launched,
          launchError: out.launchError, agentLabel: out.agentLabel, pasteHint: out.pasteHint
        });
      }

      if (p === '/api/presets' && req.method === 'GET') {
        return sendJson(res, 200, await loadPresetsConfig());
      }

      if (p === '/api/profile' && req.method === 'GET') {
        return sendJson(res, 200, await loadProfileConfig());
      }

      if (p === '/api/profile' && req.method === 'PUT') {
        const profile = sanitizeProfile(await readBodyJson(req), {});
        await writeJsonAtomic(path.join(DATA_DIR, 'profile.local.json'), profile);
        return sendJson(res, 200, { saved: true, profile });
      }

      if (p === '/api/sources' && req.method === 'GET') {
        return sendJson(res, 200, await loadSourcesConfig());
      }

      if (p === '/api/export/markdown' && req.method === 'GET') {
        const digest = await loadLatestDigest(hoursParam ? Number(hoursParam) : null);
        if (!digest) return sendJson(res, 404, { error: 'No digest available for this window' });
        const fname = `blastradius-${Number(digest.hours)}h-${String(digest.generatedAt).slice(0, 10)}.md`;
        res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'text/markdown; charset=utf-8', 'Content-Disposition': `attachment; filename="${fname}"` });
        return res.end(renderMarkdownDigest(digest));
      }

      if (p.startsWith('/api/')) throw new HttpError(404, 'Unknown API route');
      if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method not allowed');

      // Static files, confined to public/
      const rel = p === '/' ? 'index.html' : decodeURIComponent(p).replace(/^\/+/, '');
      const fullPath = path.resolve(PUBLIC_DIR, rel);
      if (fullPath !== PUBLIC_DIR && !fullPath.startsWith(PUBLIC_DIR + path.sep)) throw new HttpError(403, 'Forbidden');
      const data = await fs.readFile(fullPath);
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': MIME[path.extname(fullPath).toLowerCase()] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
      res.end(data);
    } catch (err) {
      if (err instanceof HttpError) return sendJson(res, err.status, { error: err.message });
      if (err.code === 'ENOENT' || err.code === 'EISDIR') return sendJson(res, 404, { error: 'Not found' });
      if (err instanceof URIError) return sendJson(res, 400, { error: 'Bad request' });
      console.error('[blastradius] request failed:', err);
      sendJson(res, 500, { error: 'Internal error' });
    }
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`[blastradius] Dashboard live at http://127.0.0.1:${server.address().port}`);
  });
  return server;
}

const isDirectRun = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isDirectRun) startServer();
