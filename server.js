// Mock target for CPI demos: OAuth 2.0 (client credentials) + JSON webhook receiver.
// Zero dependencies. Run: node server.js
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.CLIENT_ID || 'cpi-demo-client';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'cpi-demo-secret';
const SCOPE = process.env.SCOPE || 'sales.write';
const TOKEN_TTL = parseInt(process.env.TOKEN_TTL || '3600', 10); // seconds
const MAX_STORED = 100;

const tokens = new Map();   // token -> expiry (ms)
const received = [];        // newest first

const send = (res, code, obj, headers = {}) => {
  res.writeHead(code, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(obj));
};

const readBody = (req) => new Promise((resolve, reject) => {
  const chunks = []; let size = 0;
  req.on('data', (c) => { size += c.length; if (size > 1024 * 1024) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
  req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  req.on('error', reject);
});

function clientCredentials(req, form) {
  const auth = req.headers['authorization'] || '';
  if (auth.toLowerCase().startsWith('basic ')) {
    const [id, ...rest] = Buffer.from(auth.slice(6), 'base64').toString().split(':');
    return { id: decodeURIComponent(id), secret: decodeURIComponent(rest.join(':')) };
  }
  return { id: form.get('client_id'), secret: form.get('client_secret') };
}

async function handleToken(req, res) {
  const raw = await readBody(req);
  const form = new URLSearchParams(raw);
  if (form.get('grant_type') !== 'client_credentials') {
    return send(res, 400, { error: 'unsupported_grant_type', error_description: 'Use grant_type=client_credentials' });
  }
  const { id, secret } = clientCredentials(req, form);
  if (id !== CLIENT_ID || secret !== CLIENT_SECRET) {
    return send(res, 401, { error: 'invalid_client', error_description: 'Bad client_id or client_secret' },
      { 'WWW-Authenticate': 'Basic realm="token"' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  tokens.set(token, Date.now() + TOKEN_TTL * 1000);
  send(res, 200, { access_token: token, token_type: 'Bearer', expires_in: TOKEN_TTL, scope: SCOPE },
    { 'Cache-Control': 'no-store' });
}

function checkBearer(req, res) {
  const auth = req.headers['authorization'] || '';
  const token = auth.toLowerCase().startsWith('bearer ') ? auth.slice(7).trim() : '';
  const exp = tokens.get(token);
  if (!token || !exp || exp < Date.now()) {
    if (exp) tokens.delete(token);
    send(res, 401, { error: 'invalid_token', error_description: 'Missing, unknown or expired access token' },
      { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
    return false;
  }
  return true;
}

// Minimal XML well-formedness check (balanced tags, no parser dependency).
function xmlProblem(x) {
  const t = x.trim();
  if (!t.startsWith('<')) return 'Body is not XML';
  if (/<!DOCTYPE|<!ENTITY/i.test(t)) return 'DOCTYPE/ENTITY not allowed';
  const stack = [];
  const re = /<(\/?)([A-Za-z_][\w.\-:]*)([^<>]*?)(\/?)>/g;
  const stripped = t.replace(/<\?[\s\S]*?\?>/g, '').replace(/<!--[\s\S]*?-->/g, '');
  let m;
  while ((m = re.exec(stripped))) {
    const [, close, tag, , selfClose] = m;
    if (selfClose) continue;
    if (!close) stack.push(tag);
    else if (stack.pop() !== tag) return 'Mismatched closing tag </' + tag + '>';
  }
  return stack.length ? 'Unclosed tag <' + stack.pop() + '>' : null;
}
const xmlTag = (x, tag) => { const m = x.match(new RegExp('<' + tag + '>\\s*([^<]*?)\\s*</' + tag + '>', 'i')); return m ? m[1] : ''; };

function sendXml(res, code, xml) {
  res.writeHead(code, { 'Content-Type': 'application/xml' });
  res.end('<?xml version="1.0" encoding="UTF-8"?>' + xml);
}

const rejected = [];   // newest first
const isDate = (v) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && !isNaN(Date.parse(v)) &&
  new Date(v + 'T00:00:00Z').toISOString().slice(0, 10) === v;
const PAYMENT_MODES = ['UPI', 'CARD', 'CASH'];

function validateSalesJson(b) {
  if (!b || typeof b !== 'object' || Array.isArray(b)) return ['Body must be a JSON object'];
  const e = [];
  if (!String(b.storeId || '').trim()) e.push('storeId is required');
  if (!isDate(b.reportDate)) e.push('reportDate must be a valid yyyy-MM-dd date');
  if (typeof b.totalRevenue !== 'number' || b.totalRevenue < 0) e.push('totalRevenue must be a non-negative number');
  return e;
}

function validateSalesXml(x) {
  const e = [];
  if (!/^\s*(<\?xml[^>]*\?>\s*)?<SalesReport[\s>]/.test(x)) return ['Root element must be <SalesReport>'];
  if (!xmlTag(x, 'StoreID')) e.push('StoreID is required');
  if (!isDate(xmlTag(x, 'ReportDate'))) e.push('ReportDate must be a valid yyyy-MM-dd date');
  const txns = [...x.matchAll(/<Transaction>([\s\S]*?)<\/Transaction>/g)].map((m) => m[1]);
  if (!txns.length) e.push('At least one <Transaction> is required');
  const seen = new Set();
  txns.forEach((t, i) => {
    const id = xmlTag(t, 'TxnID');
    const label = id || '#' + (i + 1);
    if (!id) e.push('Transaction #' + (i + 1) + ': TxnID is required');
    else if (seen.has(id)) e.push('Duplicate TxnID ' + id);
    seen.add(id);
    const qty = xmlTag(t, 'Qty'), price = xmlTag(t, 'UnitPrice');
    if (!/^\d+$/.test(qty) || parseInt(qty, 10) <= 0) e.push('Invalid Qty in ' + label);
    if (!/^\d+(\.\d+)?$/.test(price) || parseFloat(price) <= 0) e.push('Invalid UnitPrice in ' + label);
    if (!PAYMENT_MODES.includes(xmlTag(t, 'PaymentMode').toUpperCase())) e.push('Invalid PaymentMode in ' + label);
  });
  return e;
}

async function handleApi(req, res, name) {
  if (!checkBearer(req, res)) return;
  const ct = (req.headers['content-type'] || '').toLowerCase();
  const isJson = ct.includes('application/json');
  const isXml = ct.includes('application/xml') || ct.includes('text/xml');
  if (!isJson && !isXml) return send(res, 415, { error: 'Content-Type must be application/json or application/xml' });

  const raw = await readBody(req);
  const reject = (code, message, details) => {
    rejected.unshift({ endpoint: '/' + name, format: isXml ? 'XML' : 'JSON', receivedAt: new Date().toISOString(),
      status: code, reasons: details || [message], sample: raw.slice(0, 300) });
    if (rejected.length > MAX_STORED) rejected.pop();
    if (isXml) {
      const d = (details || []).map((x) => `<Detail>${esc(x)}</Detail>`).join('');
      return sendXml(res, code, `<Error><Message>${esc(message)}</Message>${d ? '<Details>' + d + '</Details>' : ''}</Error>`);
    }
    return send(res, code, details ? { error: message, details } : { error: message });
  };

  if (!raw.trim()) return reject(400, 'No payload received');

  let body;
  if (isJson) {
    try { body = JSON.parse(raw); } catch { return reject(400, 'Malformed JSON'); }
  } else {
    const problem = xmlProblem(raw);
    if (problem) return reject(400, 'Malformed XML: ' + problem);
    body = raw.trim();
  }
  if (name === 'sales-report') {
    const errors = isJson ? validateSalesJson(body) : validateSalesXml(raw);
    if (errors.length) return reject(422, 'Validation failed', errors);
  }
  const entry = {
    receiptId: 'RCPT-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
    endpoint: '/' + name,
    format: isXml ? 'XML' : 'JSON',
    receivedAt: new Date().toISOString(),
    headers: {
      'content-type': req.headers['content-type'],
      'x-correlation-id': req.headers['x-correlation-id'] || null,
      'user-agent': req.headers['user-agent'] || null,
    },
    body,
  };
  received.unshift(entry);
  if (received.length > MAX_STORED) received.pop();
  if (isXml) return sendXml(res, 200, `<Receipt><Status>RECEIVED</Status><ReceiptId>${entry.receiptId}</ReceiptId><Endpoint>${entry.endpoint}</Endpoint></Receipt>`);
  send(res, 200, { status: 'RECEIVED', receiptId: entry.receiptId, endpoint: entry.endpoint });
}

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function viewer(res) {
  const rows = received.map((e) => `<div class="c"><b>${esc(e.endpoint)}</b> &middot; ${esc(e.format || 'JSON')} &middot; ${esc(e.receiptId)} &middot; ${esc(e.receivedAt)}
<pre>${esc(typeof e.body === 'string' ? e.body : JSON.stringify(e.body, null, 2))}</pre></div>`).join('') || '<p>No requests yet.</p>';
  const rejRows = rejected.map((r) => `<div class="c bad"><b>${esc(r.endpoint)}</b> &middot; ${esc(r.format)} &middot; HTTP ${r.status} &middot; ${esc(r.receivedAt)}
<ul>${r.reasons.map((x) => '<li>' + esc(x) + '</li>').join('')}</ul></div>`).join('') || '<p>None.</p>';
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="3"><title>Received payloads</title>
<style>body{font:14px Arial,sans-serif;margin:16px auto;max-width:900px;padding:0 16px}
.bad{border-color:#c0392b!important;background:#fdecea}.c{border:1px solid #ccc;border-radius:6px;padding:10px;margin:10px 0}pre{background:#f4f4f4;padding:8px;overflow:auto}</style>
<h2>Received payloads (${received.length})</h2><p>Auto-refreshes every 3 seconds. <a href="/clear">Clear</a></p>${rows}
<h2>Rejected requests (${rejected.length})</h2>${rejRows}`);
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname.replace(/\/+$/, '') || '/';
  try {
    if (req.method === 'GET' && p === '/') return send(res, 200, { service: 'cpi-demo-target', status: 'UP', endpoints: ['POST /oauth/token', 'POST /sales-report', 'POST /api/<name>', 'GET /received'] });
    if (req.method === 'POST' && p === '/oauth/token') return await handleToken(req, res);
    if (req.method === 'POST' && p === '/sales-report') return await handleApi(req, res, 'sales-report');
    const m = p.match(/^\/api\/([a-z0-9-]+)$/);
    if (req.method === 'POST' && m) return await handleApi(req, res, m[1]);
    if (req.method === 'GET' && p === '/received') return viewer(res);
    if (req.method === 'GET' && p === '/received.json') return send(res, 200, received);
    if (req.method === 'GET' && p === '/clear') { received.length = 0; rejected.length = 0; res.writeHead(302, { Location: '/received' }); return res.end(); }
    send(res, 404, { error: 'Not found' });
  } catch (e) {
    send(res, 500, { error: 'Server error' });
  }
}).listen(PORT, () => console.log(`Listening on ${PORT} | client_id=${CLIENT_ID}`));
