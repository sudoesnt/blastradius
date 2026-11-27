// Model access. One function: callModel(system, user) -> parsed JSON object.
//
// Everything sent as `user` contains untrusted text scraped from the internet, so the model runs
// with no tools and none of the operator's own agent configuration.

import { spawn } from 'node:child_process';
import os from 'node:os';

export function extractJsonObject(text) {
  const trimmed = String(text || '').trim();
  const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fence ? fence[1].trim() : trimmed;
  const start = candidate.indexOf('{');
  const end = candidate.lastIndexOf('}');
  if (start === -1 || end <= start) throw new Error('model response did not contain a JSON object');
  return JSON.parse(candidate.slice(start, end + 1));
}

export function resolveEngine(requested = 'auto') {
  if (requested && requested !== 'auto') return requested;
  if (process.env.ANTHROPIC_API_KEY) return 'anthropic';
  if (process.env.GEMINI_API_KEY) return 'gemini';
  if (process.env.OPENAI_API_KEY) return 'openai';
  return 'claude-cli';
}

/**
 * Local Claude Code CLI in print mode, locked down:
 *  --tools ""                 no built-in tools (no file, shell or web access)
 *  --strict-mcp-config        no MCP servers (none are passed)
 *  --setting-sources ""       ignore user/project/local settings, so no hooks, plugins or CLAUDE.md memory
 *  --disable-slash-commands   no skills or commands
 *  --system-prompt            replace the agent system prompt instead of appending to it
 *  --no-session-persistence   feed text is not written into the session history
 * and it runs in the OS temp directory so no project instructions are picked up from the working directory.
 */
export const CLAUDE_CLI_ARGS = [
  '-p',
  '--output-format', 'text',
  '--tools', '',
  '--strict-mcp-config',
  '--setting-sources', '',
  '--disable-slash-commands',
  '--no-session-persistence'
];

function runClaudeCli(systemPrompt, userPayload, timeoutMs) {
  return new Promise((resolve, reject) => {
    const args = [...CLAUDE_CLI_ARGS, '--system-prompt', systemPrompt];
    if (process.env.BLASTRADIUS_CLAUDE_MODEL) args.push('--model', process.env.BLASTRADIUS_CLAUDE_MODEL);
    const child = spawn('claude', args, { stdio: ['pipe', 'pipe', 'pipe'], shell: false, cwd: os.tmpdir(), windowsHide: true });

    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`claude CLI timed out after ${Math.round(timeoutMs / 1000)}s`));
    }, timeoutMs);

    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err.code === 'ENOENT' ? new Error('claude CLI not found on PATH') : err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(`claude CLI exited ${code}: ${(stderr || stdout).slice(0, 300)}`));
      resolve(stdout);
    });
    child.stdin.on('error', () => {});
    child.stdin.end(userPayload);
  });
}

async function runAnthropicApi(systemPrompt, userPayload) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'anthropic-beta': 'server-side-fallback-2026-07-01'
    },
    body: JSON.stringify({
      model: process.env.ANTHROPIC_MODEL || 'claude-opus-5-5',
      max_tokens: 16000,
      output_config: { effort: process.env.ANTHROPIC_EFFORT || 'medium' },
      fallbacks: 'default',
      system: systemPrompt,
      messages: [{ role: 'user', content: userPayload }]
    })
  });
  if (!res.ok) throw new Error(`Anthropic API HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const data = await res.json();
  if (data.stop_reason === 'refusal') throw new Error(`Anthropic API declined the request (${data.stop_details?.category || 'refusal'})`);
  if (data.stop_reason === 'max_tokens') throw new Error('Anthropic API response was cut off at max_tokens');
  return (data.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
}

async function runGeminiApi(systemPrompt, userPayload) {
  const model = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-goog-api-key': process.env.GEMINI_API_KEY },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: systemPrompt }] },
      contents: [{ role: 'user', parts: [{ text: userPayload }] }],
      generationConfig: { responseMimeType: 'application/json' }
    })
  });
  if (!res.ok) throw new Error(`Gemini API HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.map((p) => p.text || '').join('\n') || '';
}

async function runOpenAiApi(systemPrompt, userPayload) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'content-type': 'application/json', Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
    body: JSON.stringify({
      model: process.env.OPENAI_MODEL || 'gpt-4.1',
      response_format: { type: 'json_object' },
      messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userPayload }]
    })
  });
  if (!res.ok) throw new Error(`OpenAI API HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return (await res.json()).choices?.[0]?.message?.content || '';
}

export async function callModel(engine, systemPrompt, userPayload, { timeoutMs = 240000 } = {}) {
  let text;
  if (engine === 'anthropic') text = await runAnthropicApi(systemPrompt, userPayload);
  else if (engine === 'gemini') text = await runGeminiApi(systemPrompt, userPayload);
  else if (engine === 'openai') text = await runOpenAiApi(systemPrompt, userPayload);
  else if (engine === 'claude-cli') text = await runClaudeCli(systemPrompt, userPayload, timeoutMs);
  else throw new Error(`unknown engine "${engine}"`);
  return extractJsonObject(text);
}

/** Run `fn` over `list` with at most `limit` in flight. Results keep input order; failures are returned, not thrown. */
export async function mapLimit(list, limit, fn) {
  const out = new Array(list.length);
  let next = 0;
  const worker = async () => {
    while (next < list.length) {
      const i = next++;
      try { out[i] = { ok: true, value: await fn(list[i], i) }; } catch (error) { out[i] = { ok: false, error }; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, list.length) }, worker));
  return out;
}
