export type AuthScreen = "login" | "registration";

export type TokenResponse = {
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
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
  storeTokens(token: TokenResponse): void;
  clear(): void;
};

export type TransactionKeys = {
  state: string;
  verifier: string;
  continuation: string;
  prefix: string;
};

export type BrowserAuthClientConfig = {
  authorizationServerUrl: string;
  clientId: string;
  redirectUri: string | (() => string);
  scopes: string;
  sessionStore: AuthSessionStore;
  transactionStorage: StorageLike;
  transactionKeys?: Partial<TransactionKeys>;
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
  clearSession(): void;
  clearAuthorizationState(): void;
  getAccessToken(): string | null;
};
