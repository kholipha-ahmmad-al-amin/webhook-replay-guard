import test from 'node:test';
import { Readable } from 'node:stream';
import assert from 'node:assert/strict';
import { createSignatureHeader, verifyWebhook } from '../src/index.js';
import { InMemoryReplayStore } from '../src/memory-replay-store.js';
import { createWebhookServer } from '../src/http-server.js';

const SECRET = Buffer.alloc(32, 0x41);
const PREVIOUS_SECRET = Buffer.alloc(32, 0x52);
const NOW_MS = Date.now();
const NOW_SECONDS = Math.floor(NOW_MS / 1_000);
const BODY = Buffer.from('{ "type": "invoice.paid", "amount": 4200 }', 'utf8');

function makeStore(options = {}) {
  return new InMemoryReplayStore({ now: () => NOW_MS, ...options });
}

function makeHeader({ secret = SECRET, eventId = 'evt_123', timestamp = NOW_SECONDS, rawBody = BODY } = {}) {
  return createSignatureHeader({ secret, eventId, timestamp, rawBody });
}

function verify({
  header = makeHeader(),
  rawBody = BODY,
  secrets = [SECRET],
  replayStore = makeStore(),
  ...options
} = {}) {
  return verifyWebhook({
    header,
    rawBody,
    secrets,
    replayStore,
    now: () => NOW_MS,
    ...options,
  });
}

test('accepts an authentic signature over exact raw bytes', async () => {
  const result = await verify();
  assert.equal(result.ok, true);
  assert.equal(result.code, 'verified');
  assert.equal(result.eventId, 'evt_123');
  assert.equal(result.timestamp, NOW_SECONDS);
});

test('rejects a payload whose bytes changed after signing', async () => {
  const result = await verify({ rawBody: Buffer.from(BODY.toString('utf8').replace('4200', '4201')) });
  assert.deepEqual(result, { ok: false, code: 'signature_mismatch' });
});

test('accepts overlapping key rotation without requiring a key identifier', async () => {
  const current = makeHeader({ secret: SECRET });
  const previous = makeHeader({ secret: PREVIOUS_SECRET });
  const currentMac = current.split(',').find((part) => part.startsWith('v1=')).slice(3);
  const previousMac = previous.split(',').find((part) => part.startsWith('v1=')).slice(3);
  const dual = `t=${NOW_SECONDS},id=evt_123,v1=${previousMac},v1=${currentMac}`;
  const result = await verify({ header: dual, secrets: [SECRET, PREVIOUS_SECRET] });
  assert.equal(result.ok, true);
});

test('rejects event ID tampering because the ID is part of the HMAC input', async () => {
  const result = await verify({ header: makeHeader().replace('id=evt_123', 'id=evt_other') });
  assert.equal(result.code, 'signature_mismatch');
});

test('rejects stale and excessively future-dated signatures', async () => {
  const stale = makeHeader({ timestamp: NOW_SECONDS - 301 });
  const future = makeHeader({ timestamp: NOW_SECONDS + 301 });
  assert.equal((await verify({ header: stale })).code, 'timestamp_outside_window');
  assert.equal((await verify({ header: future })).code, 'timestamp_outside_window');
});

test('rejects duplicate deliveries using the replay-store claim', async () => {
  const replayStore = makeStore();
  const header = makeHeader();
  assert.equal((await verify({ header, replayStore })).ok, true);
  assert.deepEqual(await verify({ header, replayStore }), { ok: false, code: 'replay_detected' });
});

test('does not call the replay store for an invalid signature', async () => {
  let claimCalls = 0;
  const replayStore = { claim() { claimCalls += 1; return true; } };
  const result = await verify({ header: makeHeader(), secrets: [PREVIOUS_SECRET], replayStore });
  assert.equal(result.code, 'signature_mismatch');
  assert.equal(claimCalls, 0);
});

test('rejects malformed headers and non-byte bodies', async () => {
  assert.equal((await verify({ header: 't=abc,id=evt_123,v1=00' })).code, 'invalid_header');
  assert.equal((await verify({ rawBody: { type: 'invoice.paid' } })).code, 'invalid_body');
});

test('fails closed when the replay store is full or unavailable', async () => {
  const replayStore = makeStore({ maxEntries: 1 });
  assert.equal((await verify({ header: makeHeader({ eventId: 'evt_first' }), replayStore })).ok, true);
  const result = await verify({ header: makeHeader({ eventId: 'evt_second' }), replayStore });
  assert.deepEqual(result, { ok: false, code: 'replay_store_unavailable' });
});

test('enforces the configured raw-body size limit', async () => {
  const result = await verify({ maxBodyBytes: 8 });
  assert.deepEqual(result, { ok: false, code: 'payload_too_large' });
});

test('requires at least 32 bytes per HMAC secret', async () => {
  await assert.rejects(
    verifyWebhook({ header: makeHeader(), rawBody: BODY, secrets: ['short'], replayStore: makeStore() }),
    /at least 32 bytes/,
  );
});

function fakeRequest(rawBody, signature) {
  const request = Readable.from([rawBody]);
  request.method = 'POST';
  request.url = '/webhooks';
  request.headers = {
    'content-length': String(rawBody.length),
    'x-webhook-signature': signature,
  };
  return request;
}

function fakeResponse() {
  return {
    statusCode: 0,
    headers: {},
    body: Buffer.alloc(0),
    writeHead(statusCode, headers) {
      this.statusCode = statusCode;
      this.headers = headers;
    },
    end(body) {
      this.body = Buffer.from(body);
      this.writableEnded = true;
    },
  };
}

async function invokeHandler(server, request) {
  const response = fakeResponse();
  const handler = server.listeners('request')[0];
  await handler(request, response);
  return response;
}

test('HTTP receiver acknowledges once and rejects the replay in-process', async () => {
  const server = createWebhookServer({
    secrets: [SECRET],
    replayStore: makeStore(),
    namespace: 'test',
    now: () => NOW_MS,
  });
  const header = makeHeader();
  const first = await invokeHandler(server, fakeRequest(BODY, header));
  const replay = await invokeHandler(server, fakeRequest(BODY, header));
  assert.equal(first.statusCode, 202);
  assert.equal(replay.statusCode, 409);
  assert.equal(JSON.parse(replay.body.toString()).code, 'replay_detected');
});

test('HTTP receiver returns 413 for an oversized body in-process', async () => {
  const server = createWebhookServer({
    secrets: [SECRET],
    replayStore: makeStore(),
    maxBodyBytes: 8,
    now: () => NOW_MS,
  });
  const largeBody = Buffer.from('0123456789abcdef');
  const header = makeHeader({ rawBody: largeBody });
  const response = await invokeHandler(server, fakeRequest(largeBody, header));
  assert.equal(response.statusCode, 413);
  assert.equal(JSON.parse(response.body.toString()).code, 'payload_too_large');
});