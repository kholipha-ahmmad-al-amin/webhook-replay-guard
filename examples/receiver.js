import { createWebhookServer } from '../src/http-server.js';
import { InMemoryReplayStore } from '../src/memory-replay-store.js';

const currentSecret = process.env.WEBHOOK_SECRET;
if (!currentSecret) {
  throw new Error('Set WEBHOOK_SECRET to a random secret containing at least 32 bytes.');
}

const secrets = [currentSecret];
if (process.env.WEBHOOK_PREVIOUS_SECRET) secrets.push(process.env.WEBHOOK_PREVIOUS_SECRET);
const port = Number(process.env.PORT ?? '3000');
if (!Number.isInteger(port) || port < 1 || port > 65_535) {
  throw new Error('PORT must be an integer between 1 and 65535.');
}

const server = createWebhookServer({
  secrets,
  replayStore: new InMemoryReplayStore({ maxEntries: 50_000 }),
  namespace: process.env.REPLAY_NAMESPACE ?? 'demo',
  path: '/webhooks',
  maxBodyBytes: 1_048_576,
  toleranceSeconds: 300,
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Example receiver listening on http://127.0.0.1:${port}/webhooks`);
  console.log('The in-memory replay store is process-local and is not for horizontal production deployments.');
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => server.close(() => process.exit(0)));
}