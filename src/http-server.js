import { createServer } from 'node:http';
import { verifyWebhook } from './index.js';

export class PayloadTooLargeError extends Error {
  constructor() {
    super('Request body exceeds configured limit');
    this.name = 'PayloadTooLargeError';
    this.code = 'PAYLOAD_TOO_LARGE';
  }
}

/** Read exact request bytes while bounding retained memory. */
export function readRawBody(request, maxBodyBytes) {
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 0) {
    throw new TypeError('maxBodyBytes must be a non-negative safe integer');
  }

  return new Promise((resolve, reject) => {
    const declaredLength = request.headers['content-length'];
    let oversized = typeof declaredLength === 'string'
      && /^\d+$/.test(declaredLength)
      && Number(declaredLength) > maxBodyBytes;
    let total = 0;
    const chunks = [];

    request.on('data', (chunk) => {
      if (oversized) return;
      if (chunk.length > maxBodyBytes - total) {
        oversized = true;
        chunks.length = 0;
        return;
      }
      total += chunk.length;
      chunks.push(chunk);
    });
    request.once('end', () => {
      if (oversized) reject(new PayloadTooLargeError());
      else resolve(Buffer.concat(chunks, total));
    });
    request.once('error', reject);
    request.once('aborted', () => reject(new Error('Request was aborted')));
  });
}

function sendJson(response, statusCode, value) {
  const bytes = Buffer.from(JSON.stringify(value));
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': bytes.length,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  response.end(bytes);
}

function statusFor(code) {
  switch (code) {
    case 'invalid_header':
    case 'invalid_body':
      return 400;
    case 'payload_too_large':
      return 413;
    case 'replay_detected':
      return 409;
    case 'replay_store_unavailable':
    case 'clock_unavailable':
      return 503;
    default:
      return 401;
  }
}

/**
 * Build a small example receiver. Bind it to a private interface and put a
 * production reverse proxy, TLS, rate limits, and a shared replay store in front.
 */
export function createWebhookServer({
  secrets,
  replayStore,
  namespace = 'default',
  path = '/webhooks',
  maxBodyBytes = 1_048_576,
  toleranceSeconds = 300,
  now = Date.now,
} = {}) {
  if (!Array.isArray(secrets) || secrets.length < 1 || secrets.length > 5) {
    throw new TypeError('secrets must contain between 1 and 5 keys');
  }
  for (const [index, secret] of secrets.entries()) {
    const length = typeof secret === 'string'
      ? Buffer.byteLength(secret, 'utf8')
      : (Buffer.isBuffer(secret) || secret instanceof Uint8Array ? secret.byteLength : 0);
    if (length < 32) throw new TypeError(`Secret at index ${index} must contain at least 32 bytes`);
  }
  if (!replayStore || typeof replayStore.claim !== 'function') {
    throw new TypeError('replayStore must implement claim(key, expiresAtMs)');
  }
  if (typeof path !== 'string' || !/^\/[A-Za-z0-9/_-]*$/.test(path)) {
    throw new TypeError('path must be a simple absolute URL path');
  }
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 0) {
    throw new TypeError('maxBodyBytes must be a non-negative safe integer');
  }

  return createServer({
    maxHeaderSize: 8_192,
    headersTimeout: 5_000,
    requestTimeout: 15_000,
  }, async (request, response) => {
    if (request.method !== 'POST' || request.url !== path) {
      sendJson(response, 404, { ok: false, code: 'not_found' });
      return;
    }

    let rawBody;
    try {
      rawBody = await readRawBody(request, maxBodyBytes);
    } catch (error) {
      const tooLarge = error instanceof PayloadTooLargeError;
      sendJson(response, tooLarge ? 413 : 400, {
        ok: false,
        code: tooLarge ? 'payload_too_large' : 'invalid_request',
      });
      return;
    }

    const header = request.headers['x-webhook-signature'];
    if (typeof header !== 'string') {
      sendJson(response, 400, { ok: false, code: 'invalid_header' });
      return;
    }

    try {
      const result = await verifyWebhook({
        header,
        rawBody,
        secrets,
        replayStore,
        namespace,
        maxBodyBytes,
        toleranceSeconds,
        now,
      });
      if (!result.ok) {
        sendJson(response, statusFor(result.code), { ok: false, code: result.code });
        return;
      }
      // Replace this acknowledgement with an idempotent application dispatch.
      sendJson(response, 202, { ok: true, eventId: result.eventId });
    } catch {
      // Configuration and adapter failures fail closed without exposing internals.
      sendJson(response, 503, { ok: false, code: 'verification_unavailable' });
    }
  });
}