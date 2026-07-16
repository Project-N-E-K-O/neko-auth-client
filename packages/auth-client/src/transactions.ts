import type { StorageLike, TransactionKeys } from "./types.js";

export type OAuthTransaction = {
  verifier: string;
  next: string;
  createdAt?: number;
};

export const DEFAULT_TRANSACTION_KEYS: TransactionKeys = {
  state: "nekoAuthState",
  verifier: "nekoAuthCodeVerifier",
  continuation: "nekoAuthContinuation",
  prefix: "nekoAuthTx:",
};

export const DEFAULT_TRANSACTION_TTL_MS = 30 * 60 * 1000;

export function pruneOAuthTransactions(
  storage: StorageLike,
  prefix: string,
  currentTime: number,
  maxAgeMs = DEFAULT_TRANSACTION_TTL_MS,
) {
  const expiresAt = currentTime - maxAgeMs;
  for (let index = storage.length - 1; index >= 0; index -= 1) {
    const key = storage.key(index);
    if (!key?.startsWith(prefix)) {
      continue;
    }
    try {
      const value = JSON.parse(storage.getItem(key) || "{}") as Partial<OAuthTransaction>;
      if (
        typeof value.createdAt !== "number"
        || !Number.isFinite(value.createdAt)
        || value.createdAt < expiresAt
        || value.createdAt > currentTime
      ) {
        storage.removeItem(key);
      }
    } catch {
      storage.removeItem(key);
    }
  }
}

export function readOAuthTransaction(storage: StorageLike, prefix: string, state: string | null): OAuthTransaction | null {
  if (!state) {
    return null;
  }
  try {
    const raw = storage.getItem(`${prefix}${state}`);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as Partial<OAuthTransaction>;
    if (typeof parsed.verifier !== "string" || typeof parsed.next !== "string") {
      return null;
    }
    return {
      verifier: parsed.verifier,
      next: parsed.next,
      createdAt: typeof parsed.createdAt === "number" ? parsed.createdAt : undefined,
    };
  } catch {
    return null;
  }
}

export function isOAuthTransactionWithinAge(
  transaction: OAuthTransaction | null,
  currentTime: number,
  maxAgeMs: number,
) {
  if (!transaction || typeof transaction.createdAt !== "number" || !Number.isFinite(transaction.createdAt)) {
    return false;
  }
  const age = currentTime - transaction.createdAt;
  return age >= 0 && age <= maxAgeMs;
}

export function removeOAuthTransaction(storage: StorageLike, prefix: string, state: string | null) {
  if (state) {
    storage.removeItem(`${prefix}${state}`);
  }
}

export function clearLegacyTransaction(storage: StorageLike, keys: TransactionKeys) {
  storage.removeItem(keys.state);
  storage.removeItem(keys.verifier);
  storage.removeItem(keys.continuation);
}

export function clearOAuthTransactions(storage: StorageLike, prefix: string) {
  for (let index = storage.length - 1; index >= 0; index -= 1) {
    const key = storage.key(index);
    if (key?.startsWith(prefix)) {
      storage.removeItem(key);
    }
  }
}
