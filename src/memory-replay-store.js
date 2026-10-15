/**
 * Process-local replay store for development and single-process deployments.
 * Production multi-instance services should provide a shared atomic store.
 */
export class ReplayStoreCapacityError extends Error {
  constructor() {
    super('Replay store capacity reached');
    this.name = 'ReplayStoreCapacityError';
    this.code = 'REPLAY_STORE_CAPACITY';
  }
}

export class InMemoryReplayStore {
  #entries = new Map();
  #maxEntries;
  #now;
  #operations = 0;

  constructor({ maxEntries = 100_000, now = Date.now } = {}) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new TypeError('maxEntries must be a positive safe integer');
    }
    if (typeof now !== 'function') {
      throw new TypeError('now must be a function returning epoch milliseconds');
    }
    this.#maxEntries = maxEntries;
    this.#now = now;
  }

  /**
   * Atomically claim a key until expiresAtMs. Returns false when an unexpired
   * claim already exists. The synchronous Map update is atomic in one Node.js
   * event loop; it is not shared across processes or restarts.
   */
  claim(key, expiresAtMs) {
    if (typeof key !== 'string' || key.length === 0) {
      throw new TypeError('key must be a non-empty string');
    }
    if (!Number.isSafeInteger(expiresAtMs)) {
      throw new TypeError('expiresAtMs must be a safe integer');
    }
    const nowMs = this.#now();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
      throw new TypeError('Replay store clock returned an invalid time');
    }

    const currentExpiry = this.#entries.get(key);
    if (currentExpiry !== undefined && currentExpiry > nowMs) return false;
    this.#entries.delete(key);

    this.#operations += 1;
    if (this.#operations % 128 === 0 || this.#entries.size >= this.#maxEntries) {
      this.#removeExpired(nowMs);
    }
    if (this.#entries.size >= this.#maxEntries) {
      throw new ReplayStoreCapacityError();
    }

    this.#entries.set(key, expiresAtMs);
    return true;
  }

  get size() {
    return this.#entries.size;
  }

  #removeExpired(nowMs) {
    for (const [key, expiry] of this.#entries) {
      if (expiry <= nowMs) this.#entries.delete(key);
    }
  }
}