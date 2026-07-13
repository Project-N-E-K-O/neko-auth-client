import { pkceChallenge, randomString } from "./pkce.js";
import {
  clearLegacyTransaction,
  clearOAuthTransactions,
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
  TokenResponse,
} from "./types.js";

export type {
  AuthScreen,
  AuthSessionStore,
  BeginAuthorizationOptions,
  BrowserAuthClient,
  BrowserAuthClientConfig,
  StorageLike,
  TokenResponse,
  TransactionKeys,
} from "./types.js";

export function createBrowserAuthClient(config: BrowserAuthClientConfig): BrowserAuthClient {
  const authorizationServerUrl = config.authorizationServerUrl.replace(/\/+$/, "");
  const transactionKeys = { ...DEFAULT_TRANSACTION_KEYS, ...config.transactionKeys };
  const runtimeCrypto = config.runtime?.crypto ?? globalThis.crypto;
  const runtimeFetch = config.runtime?.fetch ?? globalThis.fetch.bind(globalThis);
  const now = config.runtime?.now ?? Date.now;
  const navigation = config.navigation ?? {
    assign: (url: string) => window.location.assign(url),
  };
  let authorizationStartInFlight: Promise<string> | null = null;
  let refreshInFlight: Promise<string | null> | null = null;

  function postForm(path: string, body: URLSearchParams) {
    return runtimeFetch(`${authorizationServerUrl}${path}`, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      body,
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
    pruneOAuthTransactions(config.transactionStorage, transactionKeys.prefix, now());

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
      throw new Error(`Hydra token exchange failed: ${response.status} ${await response.text()}`);
    }

    const token = await response.json() as TokenResponse;
    requireAccessToken(token);
    config.sessionStore.storeTokens(token);
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
    const transaction = readOAuthTransaction(config.transactionStorage, transactionKeys.prefix, state);
    const continuation = transaction?.next
      ?? config.transactionStorage.getItem(transactionKeys.continuation)
      ?? "";
    removeOAuthTransaction(config.transactionStorage, transactionKeys.prefix, state);
    clearLegacyTransaction(config.transactionStorage, transactionKeys);
    return { continuation };
  }

  function refreshAccessToken() {
    if (refreshInFlight) {
      return refreshInFlight;
    }

    refreshInFlight = refreshAccessTokenOnce().finally(() => {
      refreshInFlight = null;
    });
    return refreshInFlight;
  }

  async function refreshAccessTokenOnce() {
    const refreshToken = config.sessionStore.getRefreshToken();
    if (!refreshToken) {
      return null;
    }

    const response = await postForm("/oauth2/token", new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: config.clientId,
    }));
    if (!response.ok) {
      clearSession();
      return null;
    }

    try {
      const token = await response.json() as TokenResponse;
      requireAccessToken(token);
      config.sessionStore.storeTokens(token);
      return token.access_token ?? null;
    } catch {
      clearSession();
      return null;
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
    await Promise.allSettled([
      accessToken ? revokeToken(accessToken, "access_token") : undefined,
      refreshToken ? revokeToken(refreshToken, "refresh_token") : undefined,
    ]);
    clearSession();
  }

  async function revokeToken(token: string, tokenTypeHint: "access_token" | "refresh_token") {
    const response = await postForm("/oauth2/revoke", new URLSearchParams({
      token,
      token_type_hint: tokenTypeHint,
      client_id: config.clientId,
    }));
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
