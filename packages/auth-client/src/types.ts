export type AuthScreen = "login" | "registration";

export type TokenResponse = {
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
};

export type TokenGrantType = "authorization_code" | "refresh_token";

export type TokenStoreContext = {
  grantType: TokenGrantType;
};

export type RevocableTokens = {
  accessToken?: string | null;
  refreshToken?: string | null;
};

export type StorageLike = {
  readonly length: number;
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  key(index: number): string | null;
};

export type AuthSessionStore = {
  getAccessToken(): string | null;
  getRefreshToken(): string | null;
  storeTokens(token: TokenResponse, context?: TokenStoreContext): void;
  clear(): void;
};

export type TransactionKeys = {
  state: string;
  verifier: string;
  continuation: string;
  prefix: string;
};

export type RefreshCoordinator = {
  runExclusive<T>(task: () => Promise<T>): Promise<T>;
};

export type BrowserAuthClientConfig = {
  authorizationServerUrl: string;
  clientId: string;
  redirectUri: string | (() => string);
  scopes: string;
  sessionStore: AuthSessionStore;
  transactionStorage: StorageLike;
  transactionKeys?: Partial<TransactionKeys>;
  /**
   * Opt in to rejecting callbacks whose state-bound transaction is older than
   * this many milliseconds. Omit to preserve browser-auth-v1 callback
   * compatibility for consumers that still use the legacy transaction keys.
   */
  transactionMaxAgeMs?: number;
  /**
   * Keep the current session and reject refresh when Hydra is temporarily
   * unavailable (5xx or 429). Omit/false to preserve browser-auth-v1 behavior.
   * Network failures always reject without clearing the session.
   */
  preserveSessionOnServerError?: boolean;
  /**
   * Reject every non-definitive refresh failure without clearing the current
   * session. Only explicit OAuth credential failures (for example
   * `invalid_grant`) clear it. This is opt-in so browser-auth-v1 consumers keep
   * their existing default error semantics.
   */
  preserveSessionOnRefreshError?: boolean;
  /**
   * Bound OAuth token/revocation HTTP requests. Omit to preserve the
   * browser-auth-v1 unbounded request behavior.
   */
  oauthRequestTimeoutMs?: number;
  /**
   * Optional cross-client/tab mutex. The SDK rechecks the refresh-token
   * snapshot inside the critical section, so a rotated family is reused
   * instead of submitted twice.
   */
  refreshCoordinator?: RefreshCoordinator;
  /**
   * Clear local session state before starting best-effort token revocation.
   * Revocation is bounded by `revokeTimeoutMs`, preventing a slow response for
   * an old account from delaying or clearing a replacement session.
   */
  localFirstRevoke?: boolean;
  /** Timeout for `localFirstRevoke`, in milliseconds. Defaults to 3000. */
  revokeTimeoutMs?: number;
  navigation?: { assign(url: string): void };
  onSessionChanged?: () => void;
  runtime?: {
    crypto?: Crypto;
    fetch?: typeof globalThis.fetch;
    now?: () => number;
  };
};

export type BeginAuthorizationOptions = {
  screen?: AuthScreen;
  continuation?: string;
};

export type BrowserAuthClient = {
  beginAuthorization(options?: BeginAuthorizationOptions): Promise<string>;
  completeCallback(search: string): Promise<{ continuation: string }>;
  cancelAuthorization(search: string): { continuation: string };
  refreshAccessToken(): Promise<string | null>;
  revokeSession(): Promise<void>;
  /** Bounded best-effort revocation without reading or clearing session state. */
  revokeTokens(tokens: RevocableTokens): Promise<void>;
  clearSession(): void;
  clearAuthorizationState(): void;
  getAccessToken(): string | null;
};
