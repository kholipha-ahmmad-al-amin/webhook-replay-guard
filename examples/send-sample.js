import { createSignatureHeader } from '../src/index.js';
import { randomUUID } from 'node:crypto';

const secret = process.env.WEBHOOK_SECRET;
if (!secret) throw new Error('Set WEBHOOK_SECRET to the same value used by the receiver.');

const rawBody = Buffer.from(JSON.stringify({ type: 'invoice.paid', amount: 4200, currency: 'USD' }));
const timestamp = Math.floor(Date.now() / 1_000);
const eventId = `evt_${randomUUID().replaceAll('-', '')}`;
const signature = createSignatureHeader({ secret, eventId, timestamp, rawBody });
const response = await fetch(`http://127.0.0.1:${process.env.PORT ?? '3000'}/webhooks`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'x-webhook-signature': signature,
  },
  body: rawBody,
});

console.log(`${response.status} ${await response.text()}`);
if (!response.ok) process.exitCode = 1;