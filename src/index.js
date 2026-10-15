import { createHmac, timingSafeEqual } from 'node:crypto';

const MAX_HEADER_LENGTH = 2_048;
const MAX_SIGNATURES = 5;
const MAX_SECRETS = 5;
const DEFAULT_MAX_BODY_BYTES = 1_048_576;
const EVENT_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const NAMESPACE_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

function asBodyBuffer(rawBody) {
  if (!Buffer.isBuffer(rawBody) && !(rawBody instanceof Uint8Array)) return null;
  return Buffer.from(rawBody);
}

function asSecretBuffer(secret) {
  if (typeof secret === 'string') return Buffer.from(secret, 'utf8');
  if (Buffer.isBuffer(secret) || secret instanceof Uint8Array) return Buffer.from(secret);
  throw new TypeError('Each secret must be a string, Buffer, or Uint8Array');
}

function validateSecrets(secrets) {
  if (!Array.isArray(secrets) || secrets.length < 1 || secrets.length > MAX_SECRETS) {
    throw new TypeError(`secrets must contain between 1 and ${MAX_SECRETS} keys`);
  }
  return secrets.map((secret, index) => {
    const key = asSecretBuffer(secret);
    if (key.length < 32) {
      throw new TypeError(`Secret at index ${index} must contain at least 32 bytes`);
    }
    return key;
  });
}

function validateEventId(eventId) {
  return typeof eventId === 'string' && EVENT_ID_PATTERN.test(eventId);
}

function validateTimestamp(timestamp) {
  return Number.isSafeInteger(timestamp) && timestamp > 0;
}

function parseSignatureHeader(header) {
  if (typeof header !== 'string' || header.length === 0 || header.length > MAX_HEADER_LENGTH) {
    return { error: 'invalid_header' };
  }

  let timestamp;
  let eventId;
  let sawTimestamp = false;
  let sawEventId = false;
  const signatures = [];

  for (const rawPart of header.split(',')) {
    const part = rawPart.trim();
    const separator = part.indexOf('=');
    if (separator < 1) return { error: 'invalid_header' };

    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (value.length === 0) return { error: 'invalid_header' };

    if (name === 't') {
      if (sawTimestamp || !/^\d{1,16}$/.test(value)) return { error: 'invalid_header' };
      timestamp = Number(value);
      if (!validateTimestamp(timestamp)) return { error: 'invalid_header' };
      sawTimestamp = true;
    } else if (name === 'id') {
      if (sawEventId || !validateEventId(value)) return { error: 'invalid_header' };
      eventId = value;
      sawEventId = true;
    } else if (name === 'v1') {
      if (signatures.length >= MAX_SIGNATURES || !/^[0-9a-fA-F]{64}$/.test(value)) {
        return { error: 'invalid_header' };
      }
      signatures.push(Buffer.from(value, 'hex'));
    } else {
      return { error: 'invalid_header' };
    }
  }

  if (!sawTimestamp || !sawEventId || signatures.length === 0) {
    return { error: 'invalid_header' };
  }
  return { timestamp, eventId, signatures };
}

function computeMac(secret, timestamp, eventId, rawBody) {
  const hmac = createHmac('sha256', secret);
  hmac.update(`${timestamp}.${eventId}.`, 'utf8');
  hmac.update(rawBody);
  return hmac.digest();
}

function validateSigningInput({ secret, eventId, timestamp, rawBody }) {
  const [key] = validateSecrets([secret]);
  if (!validateEventId(eventId)) {
    throw new TypeError('eventId must match [A-Za-z0-9_-]{1,128}');
  }
  if (!validateTimestamp(timestamp)) {
    throw new TypeError('timestamp must be a positive safe integer in epoch seconds');
  }
  const body = asBodyBuffer(rawBody);
  if (body === null) throw new TypeError('rawBody must be a Buffer or Uint8Array');
  return { key, body };
}

/**
 * Create a signature header. The signed bytes are exactly:
 * `${timestamp}.${eventId}.` followed by the raw request body bytes.
 */
export function createSignatureHeader({ secret, eventId, timestamp, rawBody }) {
  const input = validateSigningInput({ secret, eventId, timestamp, rawBody });
  const digest = computeMac(input.key, timestamp, eventId, input.body).toString('hex');
  return `t=${timestamp},id=${eventId},v1=${digest}`;
}

/**
 * Verify a signed delivery and claim its event ID in an atomic replay store.
 * Only a successful result proves compatibility with this verifier's envelope.
 */
export async function verifyWebhook({
  header,
  rawBody,
  secrets,
  replayStore,
  namespace = 'default',
  toleranceSeconds = 300,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  now = Date.now,
} = {}) {
  const parsed = parseSignatureHeader(header);
  if (parsed.error) return { ok: false, code: parsed.error };

  const body = asBodyBuffer(rawBody);
  if (body === null) return { ok: false, code: 'invalid_body' };
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 0) {
    throw new TypeError('maxBodyBytes must be a non-negative safe integer');
  }
  if (body.length > maxBodyBytes) return { ok: false, code: 'payload_too_large' };
  if (!Number.isSafeInteger(toleranceSeconds) || toleranceSeconds < 1 || toleranceSeconds > 86_400) {
    throw new TypeError('toleranceSeconds must be an integer between 1 and 86400');
  }
  if (!NAMESPACE_PATTERN.test(namespace)) {
    throw new TypeError('namespace must match [A-Za-z0-9._-]{1,128}');
  }
  if (typeof now !== 'function') throw new TypeError('now must be a clock function');
  if (!replayStore || typeof replayStore.claim !== 'function') {
    throw new TypeError('replayStore must implement claim(key, expiresAtMs)');
  }

  const keys = validateSecrets(secrets);
  let matched = 0;
  for (const key of keys) {
    const expected = computeMac(key, parsed.timestamp, parsed.eventId, body);
    for (const candidate of parsed.signatures) {
      // All configured key/signature pairs are compared; do not short-circuit
      // after a match, which would reveal the matching rotation slot by timing.
      matched |= Number(timingSafeEqual(expected, candidate));
    }
  }
  if (matched === 0) return { ok: false, code: 'signature_mismatch' };

  const nowMs = now();
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    return { ok: false, code: 'clock_unavailable' };
  }
  const nowSeconds = Math.floor(nowMs / 1_000);
  if (Math.abs(nowSeconds - parsed.timestamp) > toleranceSeconds) {
    return { ok: false, code: 'timestamp_outside_window' };
  }

  const replayKey = `${namespace}:${parsed.eventId}`;
  let claimed;
  try {
    claimed = await replayStore.claim(replayKey, nowMs + toleranceSeconds * 1_000);
  } catch {
    return { ok: false, code: 'replay_store_unavailable' };
  }
  if (claimed !== true) return { ok: false, code: 'replay_detected' };

  return {
    ok: true,
    code: 'verified',
    eventId: parsed.eventId,
    timestamp: parsed.timestamp,
  };
}

export const DEFAULTS = Object.freeze({
  maxBodyBytes: DEFAULT_MAX_BODY_BYTES,
  toleranceSeconds: 300,
  maxSignatures: MAX_SIGNATURES,
  maxSecrets: MAX_SECRETS,
});