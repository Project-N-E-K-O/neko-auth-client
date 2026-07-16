import { pkceChallenge, randomString } from "./pkce.js";
import {
  clearLegacyTransaction,
  clearOAuthTransactions,
  isOAuthTransactionWithinAge,
  DEFAULT_TRANSACTION_KEYS,
  pruneOAuthTransactions,
  readOAuthTransaction,
  removeOAuthTransaction,
  type OAuthTransaction,
} from "./transactions.js";
import type {
  BeginAuthorizationOptions,
  BrowserAuthClient,
  BrowserAuthClientConfig,
  RevocableTokens,
  TokenStoreContext,
  TokenResponse,
} from "./types.js";

export type {
  AuthScreen,
  AuthSessionStore,
  BeginAuthorizationOptions,
  BrowserAuthClient,
  BrowserAuthClientConfig,
  RefreshCoordinator,
  RevocableTokens,
  StorageLike,
  TokenGrantType,
  TokenResponse,
  TokenStoreContext,
  TransactionKeys,
} from "./types.js";

const DEFAULT_REVOKE_TIMEOUT_MS = 3_000;
const DEFINITIVE_REFRESH_CREDENTIAL_ERRORS = new Set([
  "invalid_grant",
  "invalid_client",
  "unauthorized_client",
]);

export class OAuthHttpError extends Error {
  readonly status: number;
  readonly oauthError: string | null;

  constructor(message: string, status: number, oauthError: string | null = null) {
    super(message);
    this.name = "OAuthHttpError";
    this.status = status;
    this.oauthError = oauthError;
  }
}

export function createBrowserAuthClient(config: BrowserAuthClientConfig): BrowserAuthClient {
  if (
    config.transactionMaxAgeMs !== undefined
    && (!Number.isFinite(config.transactionMaxAgeMs) || config.transactionMaxAgeMs <= 0)
  ) {
    throw new TypeError("transactionMaxAgeMs must be a positive finite number");
  }
  if (
    config.revokeTimeoutMs !== undefined
    && (!Number.isFinite(config.revokeTimeoutMs) || config.revokeTimeoutMs <= 0)
  ) {
    throw new TypeError("revokeTimeoutMs must be a positive finite number");
  }
  if (
    config.oauthRequestTimeoutMs !== undefined
    && (!Number.isFinite(config.oauthRequestTimeoutMs) || config.oauthRequestTimeoutMs <= 0)
  ) {
    throw new TypeError("oauthRequestTimeoutMs must be a positive finite number");
  }
  const authorizationServerUrl = config.authorizationServerUrl.replace(/\/+$/, "");
  const transactionKeys = { ...DEFAULT_TRANSACTION_KEYS, ...config.transactionKeys };
  const runtimeCrypto = config.runtime?.crypto ?? globalThis.crypto;
  const runtimeFetch = config.runtime?.fetch ?? globalThis.fetch.bind(globalThis);
  const now = config.runtime?.now ?? Date.now;
  const navigation = config.navigation ?? {
    assign: (url: string) => window.location.assign(url),
  };
  let authorizationStartInFlight: Promise<string> | null = null;
  const refreshesInFlight = new Map<string, Promise<string | null>>();

  function postForm(path: string, body: URLSearchParams, signal?: AbortSignal) {
    const request = (requestSignal?: AbortSignal) => runtimeFetch(
      `${authorizationServerUrl}${path}`,
      {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/x-www-form-urlencoded",
        },
        body,
        signal: requestSignal,
      },
    );
    const timeoutMs = config.oauthRequestTimeoutMs;
    if (timeoutMs === undefined) return request(signal);

    const abortController = new AbortController();
    let timeout: ReturnType<typeof setTimeout> | undefined;
    let onAbort: (() => void) | undefined;
    const boundary = new Promise<Response>((_resolve, reject) => {
      const abort = (reason: unknown) => {
        abortController.abort(reason);
        reject(reason);
      };
      if (signal?.aborted) {
        const error = signal.reason ?? new Error("OAuth request aborted");
        abort(error);
        return;
      }
      if (signal) {
        onAbort = () => abort(signal.reason ?? new Error("OAuth request aborted"));
        signal.addEventListener("abort", onAbort, { once: true });
      }
      timeout = setTimeout(() => {
        const error = new Error(`OAuth request timed out after ${timeoutMs}ms`);
        error.name = "TimeoutError";
        abort(error);
      }, timeoutMs);
    });
    const response = Promise.resolve().then(async () => {
      const received = await request(abortController.signal);
      // Buffer the body before releasing the deadline. Fetch resolves when
      // headers arrive, but a peer can otherwise stall json()/text() forever.
      const bodyBytes = await received.arrayBuffer();
      return new Response(bodyBytes.byteLength ? bodyBytes : null, {
        status: received.status,
        statusText: received.statusText,
        headers: received.headers,
      });
    });
    return Promise.race([response, boundary]).finally(() => {
      if (timeout !== undefined) clearTimeout(timeout);
      if (signal && onAbort) signal.removeEventListener("abort", onAbort);
    });
  }

  function beginAuthorization(options: BeginAuthorizationOptions = {}) {
    if (authorizationStartInFlight) {
      return authorizationStartInFlight;
    }

    authorizationStartInFlight = beginAuthorizationOnce(options).finally(() => {
      authorizationStartInFlight = null;
    });
    return authorizationStartInFlight;
  }

  async function beginAuthorizationOnce(options: BeginAuthorizationOptions) {
    const state = randomString(runtimeCrypto);
    const verifier = randomString(runtimeCrypto);
    const challenge = await pkceChallenge(verifier, runtimeCrypto);
    const continuation = options.continuation ?? "";

    config.transactionStorage.setItem(transactionKeys.state, state);
    config.transactionStorage.setItem(transactionKeys.verifier, verifier);
    config.transactionStorage.setItem(transactionKeys.continuation, continuation);
    config.transactionStorage.setItem(
      `${transactionKeys.prefix}${state}`,
      JSON.stringify({ verifier, next: continuation, createdAt: now() } satisfies OAuthTransaction),
    );
    pruneOAuthTransactions(
      config.transactionStorage,
      transactionKeys.prefix,
      now(),
      config.transactionMaxAgeMs,
    );

    const params = new URLSearchParams({
      client_id: config.clientId,
      response_type: "code",
      scope: config.scopes,
      redirect_uri: redirectUri(config.redirectUri),
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
      screen: options.screen ?? "login",
    });
    const authorizationUrl = `${authorizationServerUrl}/oauth2/auth?${params.toString()}`;
    navigation.assign(authorizationUrl);
    return authorizationUrl;
  }

  async function completeCallback(search: string) {
    const params = new URLSearchParams(search);
    const error = params.get("error");
    if (error) {
      throw new Error(`${error}: ${params.get("error_description") || "Ory authorization failed"}`);
    }

    const code = params.get("code");
    const state = params.get("state");
    const expectedState = config.transactionStorage.getItem(transactionKeys.state);
    const transaction = readOAuthTransaction(config.transactionStorage, transactionKeys.prefix, state);
    const verifier = transaction?.verifier
      ?? config.transactionStorage.getItem(transactionKeys.verifier);
    if (!code) {
      throw new Error("OAuth callback is missing code");
    }
    if (!state || (!transaction && (!expectedState || state !== expectedState))) {
      throw new Error("OAuth state mismatch; please start login again");
    }
    if (
      config.transactionMaxAgeMs !== undefined
      && !isOAuthTransactionWithinAge(transaction, now(), config.transactionMaxAgeMs)
    ) {
      removeOAuthTransaction(config.transactionStorage, transactionKeys.prefix, state);
      clearLegacyTransaction(config.transactionStorage, transactionKeys);
      throw new Error("OAuth transaction expired; please start login again");
    }
    if (!verifier) {
      throw new Error("OAuth code verifier is missing; please start login again");
    }

    const response = await postForm("/oauth2/token", new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri(config.redirectUri),
      code_verifier: verifier,
      client_id: config.clientId,
    }));
    if (!response.ok) {
      throw new OAuthHttpError(
        `Hydra token exchange failed: ${response.status} ${await response.text()}`,
        response.status,
      );
    }

    const token = await response.json() as TokenResponse;
    requireAccessToken(token);
    config.sessionStore.storeTokens(token, { grantType: "authorization_code" });
    removeOAuthTransaction(config.transactionStorage, transactionKeys.prefix, state);
    config.transactionStorage.removeItem(transactionKeys.state);
    config.transactionStorage.removeItem(transactionKeys.verifier);
    const continuation = transaction?.next
      ?? config.transactionStorage.getItem(transactionKeys.continuation)
      ?? "";
    config.transactionStorage.removeItem(transactionKeys.continuation);
    config.onSessionChanged?.();
    return { continuation };
  }

  function cancelAuthorization(search: string) {
    const state = new URLSearchParams(search).get("state");
    const expectedState = config.transactionStorage.getItem(transactionKeys.state);
    const transaction = readOAuthTransaction(config.transactionStorage, transactionKeys.prefix, state);
    if (!state || (!transaction && (!expectedState || state !== expectedState))) {
      throw new Error("OAuth state mismatch; please start login again");
    }
    if (
      config.transactionMaxAgeMs !== undefined
      && !isOAuthTransactionWithinAge(transaction, now(), config.transactionMaxAgeMs)
    ) {
      removeOAuthTransaction(config.transactionStorage, transactionKeys.prefix, state);
      clearLegacyTransaction(config.transactionStorage, transactionKeys);
      throw new Error("OAuth transaction expired; please start login again");
    }
    const continuation = transaction?.next
      ?? config.transactionStorage.getItem(transactionKeys.continuation)
      ?? "";
    removeOAuthTransaction(config.transactionStorage, transactionKeys.prefix, state);
    clearLegacyTransaction(config.transactionStorage, transactionKeys);
    return { continuation };
  }

  function refreshAccessToken() {
    const refreshToken = config.sessionStore.getRefreshToken();
    if (!refreshToken) {
      return Promise.resolve(null);
    }
    const existingRefresh = refreshesInFlight.get(refreshToken);
    if (existingRefresh) {
      return existingRefresh;
    }

    const refresh = refreshAccessTokenCoordinated(refreshToken).finally(() => {
      if (refreshesInFlight.get(refreshToken) === refresh) {
        refreshesInFlight.delete(refreshToken);
      }
    });
    refreshesInFlight.set(refreshToken, refresh);
    return refresh;
  }

  function refreshAccessTokenCoordinated(refreshToken: string) {
    const refresh = async () => {
      if (config.sessionStore.getRefreshToken() !== refreshToken) {
        return config.sessionStore.getAccessToken();
      }
      return refreshAccessTokenOnce(refreshToken);
    };
    return config.refreshCoordinator
      ? config.refreshCoordinator.runExclusive(refresh)
      : refresh();
  }

  async function refreshAccessTokenOnce(refreshToken: string) {
    const response = await postForm("/oauth2/token", new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: config.clientId,
    }));
    if (!response.ok) {
      const failure = await readOAuthFailure(response);
      if (config.preserveSessionOnRefreshError) {
        if (failure.oauthError && DEFINITIVE_REFRESH_CREDENTIAL_ERRORS.has(failure.oauthError)) {
          clearSessionIfRefreshTokenMatches(refreshToken);
          return null;
        }
        throw new OAuthHttpError(
          refreshFailureMessage(response.status, failure),
          response.status,
          failure.oauthError,
        );
      }
      if (config.preserveSessionOnServerError && (response.status >= 500 || response.status === 429)) {
        throw new OAuthHttpError(
          `Hydra token refresh temporarily unavailable: ${response.status}`,
          response.status,
          failure.oauthError,
        );
      }
      clearSessionIfRefreshTokenMatches(refreshToken);
      return null;
    }

    try {
      const token = await response.json() as TokenResponse;
      requireAccessToken(token);
      if (config.sessionStore.getRefreshToken() !== refreshToken) {
        return config.sessionStore.getAccessToken();
      }
      config.sessionStore.storeTokens(
        token,
        { grantType: "refresh_token" } satisfies TokenStoreContext,
      );
      return token.access_token ?? null;
    } catch (error) {
      if (config.preserveSessionOnRefreshError) {
        throw error;
      }
      clearSessionIfRefreshTokenMatches(refreshToken);
      return null;
    }
  }

  function clearSessionIfRefreshTokenMatches(refreshToken: string) {
    if (config.sessionStore.getRefreshToken() === refreshToken) {
      clearSession();
    }
  }

  function getAccessToken() {
    return config.sessionStore.getAccessToken();
  }

  function clearAuthorizationState() {
    clearLegacyTransaction(config.transactionStorage, transactionKeys);
    clearOAuthTransactions(config.transactionStorage, transactionKeys.prefix);
  }

  function clearSession() {
    config.sessionStore.clear();
    clearAuthorizationState();
    config.onSessionChanged?.();
  }

  async function revokeSession() {
    const accessToken = config.sessionStore.getAccessToken();
    const refreshToken = config.sessionStore.getRefreshToken();
    if (config.localFirstRevoke) {
      clearSession();
      await revokeTokensBestEffort(accessToken, refreshToken);
      return;
    }
    await Promise.allSettled(revokePromises(accessToken, refreshToken));
    clearSession();
  }

  function revokeTokens(tokens: RevocableTokens) {
    return revokeTokensBestEffort(
      tokens.accessToken ?? null,
      tokens.refreshToken ?? null,
    );
  }

  function revokePromises(
    accessToken: string | null,
    refreshToken: string | null,
    signal?: AbortSignal,
  ) {
    return [
      accessToken ? revokeToken(accessToken, "access_token", signal) : null,
      refreshToken ? revokeToken(refreshToken, "refresh_token", signal) : null,
    ].filter((request): request is Promise<void> => request !== null);
  }

  async function revokeTokensBestEffort(
    accessToken: string | null,
    refreshToken: string | null,
  ) {
    const abortController = new AbortController();
    const revocations = Promise.allSettled(
      revokePromises(accessToken, refreshToken, abortController.signal),
    );
    const timeoutMs = config.revokeTimeoutMs ?? DEFAULT_REVOKE_TIMEOUT_MS;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const timedOut = new Promise<void>((resolve) => {
      timeout = setTimeout(() => {
        abortController.abort();
        resolve();
      }, timeoutMs);
    });
    await Promise.race([revocations.then(() => undefined), timedOut]);
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }

  async function revokeToken(
    token: string,
    tokenTypeHint: "access_token" | "refresh_token",
    signal?: AbortSignal,
  ) {
    const response = await postForm("/oauth2/revoke", new URLSearchParams({
      token,
      token_type_hint: tokenTypeHint,
      client_id: config.clientId,
    }), signal);
    if (!response.ok) {
      throw new Error(`Hydra token revoke failed: ${response.status} ${await response.text()}`);
    }
  }

  return {
    beginAuthorization,
    completeCallback,
    cancelAuthorization,
    refreshAccessToken,
    revokeSession,
    revokeTokens,
    clearSession,
    clearAuthorizationState,
    getAccessToken,
  };
}

function redirectUri(value: string | (() => string)) {
  return typeof value === "function" ? value() : value;
}

function requireAccessToken(token: TokenResponse) {
  if (!token.access_token) {
    throw new Error("Token response did not include access_token");
  }
}

type OAuthFailure = {
  oauthError: string | null;
  description: string;
};

async function readOAuthFailure(response: Response): Promise<OAuthFailure> {
  let body = "";
  try {
    body = await response.text();
  } catch {
    return { oauthError: null, description: "" };
  }
  if (!body) {
    return { oauthError: null, description: "" };
  }
  try {
    const parsed = JSON.parse(body) as { error?: unknown; error_description?: unknown };
    return {
      oauthError: typeof parsed.error === "string" ? parsed.error : null,
      description: typeof parsed.error_description === "string"
        ? parsed.error_description
        : body,
    };
  } catch {
    return { oauthError: null, description: body };
  }
}

function refreshFailureMessage(status: number, failure: OAuthFailure) {
  const code = failure.oauthError ? ` ${failure.oauthError}` : "";
  const description = failure.description ? `: ${failure.description}` : "";
  return `Hydra token refresh failed: ${status}${code}${description}`;
}
