'use strict';

/**
 * CodeVault — Server
 * HTTP API + SSE live feed. Zero npm dependencies.
 *
 * Endpoints:
 *   POST /v1/scan          — scan code, returns findings + chain entry
 *   GET  /v1/chain         — full audit chain
 *   GET  /v1/events        — Server-Sent Events live feed
 *   GET  /health           — gateway health + chain stats
 */

const http = require('http');
const crypto = require('crypto');
const { scan } = require('./scanner');
const { enrichFindings } = require('./advisor');
const AuditChain = require('./audit_chain');

const chain = new AuditChain();
const sseClients = new Set();

// ── SSE broadcast ─────────────────────────────────────────────────────────
function broadcast(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try { res.write(msg); } catch (_) { sseClients.delete(res); }
  }
}

// ── Request handler ───────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── SSE live feed ────────────────────────────────────────────────────────
  if (req.url === '/v1/events' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    // Send current stats snapshot
    res.write(`event: snapshot\ndata: ${JSON.stringify(chain.getStats())}\n\n`);
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    const ping = setInterval(() => {
      try { res.write(': ping\n\n'); } catch (_) { clearInterval(ping); sseClients.delete(res); }
    }, 25000);
    return;
  }

  // ── Health ───────────────────────────────────────────────────────────────
  if (req.url === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'OPERATIONAL',
      ...chain.getStats(),
      uptime_seconds: Math.floor(process.uptime()),
      timestamp: new Date().toISOString(),
    }));
    return;
  }

  // ── Audit chain ──────────────────────────────────────────────────────────
  if (req.url === '/v1/chain' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ...chain.verify(),
      entries: chain.getChain(100),
    }));
    return;
  }

  // ── Scan ─────────────────────────────────────────────────────────────────
  if (req.url === '/v1/scan' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      let code = '';
      try {
        const parsed = JSON.parse(body);
        code = parsed.code || '';
      } catch (_) {
        code = body;
      }

      if (!code || typeof code !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'code field required' }));
        return;
      }

      const scanId = 'scan_' + crypto.randomBytes(8).toString('hex');
      const startMs = Date.now();

      // Run scan
      const rawResult = scan(code);
      const enriched = { ...rawResult, findings: enrichFindings(rawResult.findings) };

      // Append to forensic chain
      const chainEntry = chain.append(scanId, code, rawResult);

      const latencyMs = Date.now() - startMs;

      const response = {
        scan_id: scanId,
        timestamp: chainEntry.timestamp,
        risk_level: rawResult.risk_level,
        severity_score: rawResult.severity_score,
        finding_count: rawResult.finding_count,
        scanned_lines: rawResult.scanned_lines,
        latency_ms: latencyMs,
        findings: enriched.findings,
        forensic_receipt: {
          code_hash: chainEntry.code_hash,
          findings_hash: chainEntry.findings_hash,
          chain_hash: chainEntry.hash,
          prev_hash: chainEntry.prev_hash,
          chain_index: chainEntry.index,
        },
      };

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(response));

      // Broadcast to all SSE listeners
      broadcast('scan', {
        scan_id: scanId,
        timestamp: chainEntry.timestamp,
        risk_level: rawResult.risk_level,
        severity_score: rawResult.severity_score,
        finding_count: rawResult.finding_count,
        chain_hash: chainEntry.hash,
        ...chain.getStats(),
      });
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'NOT_FOUND', path: req.url }));
});

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`[CodeVault] Forensic Code Scanner online → http://127.0.0.1:${PORT}`);
    console.log(`[CodeVault] Live SSE feed              → http://127.0.0.1:${PORT}/v1/events`);
    console.log(`[CodeVault] Audit chain                → http://127.0.0.1:${PORT}/v1/chain`);
    console.log(`[CodeVault] Open dashboard.html in browser and connect to http://127.0.0.1:${PORT}`);
  });
}

module.exports = { server, chain };
