import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createBrowserAuthClient,
  type AuthSessionStore,
  type StorageLike,
  type TokenResponse,
  type TokenStoreContext,
} from "../src/index.js";

class MemoryStorage implements StorageLike {
  private readonly values = new Map<string, string>();

  getItem(key: string) {
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string) {
    this.values.set(key, value);
  }

  removeItem(key: string) {
    this.values.delete(key);
  }

  key(index: number) {
    return [...this.values.keys()][index] ?? null;
  }

  get length() {
    return this.values.size;
  }
}

function unusedSessionStore(): AuthSessionStore {
  return {
    getAccessToken: () => null,
    getRefreshToken: () => null,
    storeTokens: () => undefined,
    clear: () => undefined,
  };
}

function hangingBodyResponse(status = 200) {
  return new Response(new ReadableStream<Uint8Array>({
    start() { /* headers arrive, body deliberately never closes */ },
  }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

class MemorySessionStore implements AuthSessionStore {
  accessToken: string | null = null;
  refreshToken: string | null = null;
  clearCount = 0;
  storeContexts: Array<TokenStoreContext | undefined> = [];

  getAccessToken() {
    return this.accessToken;
  }

  getRefreshToken() {
    return this.refreshToken;
  }

  storeTokens(token: TokenResponse, context?: TokenStoreContext) {
    this.storeContexts.push(context);
    this.accessToken = token.access_token ?? null;
    if (token.refresh_token) {
      this.refreshToken = token.refresh_token;
    }
  }

  clear() {
    this.accessToken = null;
    this.refreshToken = null;
    this.clearCount += 1;
  }
}

describe("browser auth client", () => {
  it("starts authorization with S256 PKCE and a state-bound continuation", async () => {
    const transactionStorage = new MemoryStorage();
    const assigned: string[] = [];
    const crypto = {
      getRandomValues<T extends ArrayBufferView | null>(values: T): T {
        if (values instanceof Uint8Array) {
          values.fill(7);
        }
        return values;
      },
    } as Crypto;
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test/",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore: unusedSessionStore(),
      transactionStorage,
      transactionKeys: {
        state: "legacyState",
        verifier: "legacyVerifier",
        continuation: "legacyNext",
        prefix: "legacyTx:",
      },
      navigation: { assign: (url) => assigned.push(url) },
      runtime: { crypto, now: () => 123_456 },
    });

    const authorizationUrl = await auth.beginAuthorization({
      screen: "registration",
      continuation: "/plugins/42",
    });

    assert.deepEqual(assigned, [authorizationUrl]);
    const url = new URL(authorizationUrl);
    assert.equal(url.origin, "https://auth.neko.test");
    assert.equal(url.pathname, "/oauth2/auth");
    assert.equal(url.searchParams.get("client_id"), "neko-web");
    assert.equal(url.searchParams.get("response_type"), "code");
    assert.equal(url.searchParams.get("redirect_uri"), "https://app.neko.test/oauth/callback");
    assert.equal(url.searchParams.get("scope"), "openid profile offline");
    assert.equal(url.searchParams.get("screen"), "registration");
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.equal(url.searchParams.get("code_challenge"), "3Ev4DHdHPRMPoN6GukAY_pi7IUAF5qWJHRK6kURvnoE");
    assert.equal(url.searchParams.get("state"), transactionStorage.getItem("legacyState"));
    assert.equal(transactionStorage.getItem("legacyVerifier"), "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc");
    assert.equal(transactionStorage.getItem("legacyNext"), "/plugins/42");

    const state = transactionStorage.getItem("legacyState");
    assert.ok(state);
    assert.deepEqual(JSON.parse(transactionStorage.getItem(`legacyTx:${state}`) ?? ""), {
      verifier: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
      next: "/plugins/42",
      createdAt: 123_456,
    });
  });

  it("completes a state-bound callback and stores the exchanged tokens", async () => {
    const transactionStorage = new MemoryStorage();
    const sessionStore = new MemorySessionStore();
    transactionStorage.setItem("state", "state-1");
    transactionStorage.setItem("verifier", "verifier-1");
    transactionStorage.setItem("next", "/plugins/42");
    transactionStorage.setItem("tx:state-1", JSON.stringify({
      verifier: "verifier-1",
      next: "/plugins/42",
      createdAt: 123_456,
    }));
    let requestBody = "";
    let changedCount = 0;
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage,
      transactionKeys: { state: "state", verifier: "verifier", continuation: "next", prefix: "tx:" },
      navigation: { assign: () => undefined },
      onSessionChanged: () => { changedCount += 1; },
      runtime: {
        fetch: async (input, init) => {
          assert.equal(input, "https://auth.neko.test/oauth2/token");
          assert.equal(init?.method, "POST");
          requestBody = String(init?.body);
          return Response.json({ access_token: "access-1", refresh_token: "refresh-1" });
        },
      },
    });

    const result = await auth.completeCallback("?code=code-1&state=state-1");

    assert.deepEqual(result, { continuation: "/plugins/42" });
    assert.equal(sessionStore.accessToken, "access-1");
    assert.equal(sessionStore.refreshToken, "refresh-1");
    assert.deepEqual(sessionStore.storeContexts, [{ grantType: "authorization_code" }]);
    assert.equal(changedCount, 1);
    assert.equal(transactionStorage.getItem("state"), null);
    assert.equal(transactionStorage.getItem("verifier"), null);
    assert.equal(transactionStorage.getItem("next"), null);
    assert.equal(transactionStorage.getItem("tx:state-1"), null);
    assert.deepEqual(Object.fromEntries(new URLSearchParams(requestBody)), {
      grant_type: "authorization_code",
      code: "code-1",
      redirect_uri: "https://app.neko.test/oauth/callback",
      code_verifier: "verifier-1",
      client_id: "neko-web",
    });
  });

  it("bounds a callback whose token response body never completes", async () => {
    const transactionStorage = new MemoryStorage();
    const sessionStore = new MemorySessionStore();
    transactionStorage.setItem("state", "state-1");
    transactionStorage.setItem("verifier", "verifier-1");
    transactionStorage.setItem("tx:state-1", JSON.stringify({
      verifier: "verifier-1",
      next: "/account",
      createdAt: 123_456,
    }));
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage,
      transactionKeys: { state: "state", verifier: "verifier", continuation: "next", prefix: "tx:" },
      oauthRequestTimeoutMs: 10,
      navigation: { assign: () => undefined },
      runtime: { fetch: async () => hangingBodyResponse() },
    });

    await Promise.race([
      assert.rejects(
        () => auth.completeCallback("?code=code-1&state=state-1"),
        (error: Error) => error.name === "TimeoutError",
      ),
      new Promise<never>((_resolve, reject) => {
        setTimeout(() => reject(new Error("callback body timeout was not honored")), 250);
      }),
    ]);
    assert.equal(sessionStore.accessToken, null);
    assert.ok(transactionStorage.getItem("tx:state-1"));
  });

  it("optionally rejects expired, future, and legacy callback transactions before exchange", async () => {
    for (const createdAt of [89_999, 100_001, undefined]) {
      const transactionStorage = new MemoryStorage();
      transactionStorage.setItem("state", "state-1");
      transactionStorage.setItem("verifier", "legacy-verifier");
      transactionStorage.setItem("tx:state-1", JSON.stringify({
        verifier: "verifier-1",
        next: "/account",
        ...(createdAt === undefined ? {} : { createdAt }),
      }));
      let fetchCount = 0;
      const auth = createBrowserAuthClient({
        authorizationServerUrl: "https://auth.neko.test",
        clientId: "neko-web",
        redirectUri: "https://app.neko.test/oauth/callback",
        scopes: "openid profile offline",
        sessionStore: unusedSessionStore(),
        transactionStorage,
        transactionKeys: { state: "state", verifier: "verifier", continuation: "next", prefix: "tx:" },
        transactionMaxAgeMs: 10_000,
        navigation: { assign: () => undefined },
        runtime: {
          now: () => 100_000,
          fetch: async () => {
            fetchCount += 1;
            return Response.json({ access_token: "unexpected" });
          },
        },
      });

      await assert.rejects(
        () => auth.completeCallback("?code=code-1&state=state-1"),
        /OAuth transaction expired/,
      );
      assert.equal(fetchCount, 0);
      assert.equal(transactionStorage.getItem("tx:state-1"), null);
      assert.equal(transactionStorage.getItem("state"), null);
      assert.equal(transactionStorage.getItem("verifier"), null);
    }
  });

  it("keeps legacy callback age behavior when transactionMaxAgeMs is omitted", async () => {
    const transactionStorage = new MemoryStorage();
    const sessionStore = new MemorySessionStore();
    transactionStorage.setItem("state", "state-1");
    transactionStorage.setItem("verifier", "verifier-1");
    transactionStorage.setItem("tx:state-1", JSON.stringify({
      verifier: "verifier-1",
      next: "/account",
      createdAt: 1,
    }));
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage,
      transactionKeys: { state: "state", verifier: "verifier", continuation: "next", prefix: "tx:" },
      navigation: { assign: () => undefined },
      runtime: {
        now: () => 100_000,
        fetch: async () => Response.json({ access_token: "access-1" }),
      },
    });

    await assert.doesNotReject(() => auth.completeCallback("?code=code-1&state=state-1"));
    assert.equal(sessionStore.accessToken, "access-1");
  });

  it("rejects invalid transactionMaxAgeMs configuration", () => {
    assert.throws(
      () => createBrowserAuthClient({
        authorizationServerUrl: "https://auth.neko.test",
        clientId: "neko-web",
        redirectUri: "https://app.neko.test/oauth/callback",
        scopes: "openid",
        sessionStore: unusedSessionStore(),
        transactionStorage: new MemoryStorage(),
        transactionMaxAgeMs: 0,
      }),
      /transactionMaxAgeMs/,
    );
    assert.throws(
      () => createBrowserAuthClient({
        authorizationServerUrl: "https://auth.neko.test",
        clientId: "neko-web",
        redirectUri: "https://app.neko.test/oauth/callback",
        scopes: "openid",
        sessionStore: unusedSessionStore(),
        transactionStorage: new MemoryStorage(),
        revokeTimeoutMs: Number.NaN,
      }),
      /revokeTimeoutMs/,
    );
    assert.throws(
      () => createBrowserAuthClient({
        authorizationServerUrl: "https://auth.neko.test",
        clientId: "neko-web",
        redirectUri: "https://app.neko.test/oauth/callback",
        scopes: "openid",
        sessionStore: unusedSessionStore(),
        transactionStorage: new MemoryStorage(),
        oauthRequestTimeoutMs: Number.POSITIVE_INFINITY,
      }),
      /oauthRequestTimeoutMs/,
    );
  });

  it("deduplicates concurrent refreshes and stores rotated tokens", async () => {
    const transactionStorage = new MemoryStorage();
    const sessionStore = new MemorySessionStore();
    sessionStore.refreshToken = "refresh-1";
    let fetchCount = 0;
    let requestBody = "";
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage,
      navigation: { assign: () => undefined },
      runtime: {
        fetch: async (_input, init) => {
          fetchCount += 1;
          requestBody = String(init?.body);
          await new Promise((resolve) => setTimeout(resolve, 5));
          return Response.json({ access_token: "access-2", refresh_token: "refresh-2" });
        },
      },
    });

    const [first, second] = await Promise.all([
      auth.refreshAccessToken(),
      auth.refreshAccessToken(),
    ]);

    assert.equal(first, "access-2");
    assert.equal(second, "access-2");
    assert.equal(fetchCount, 1);
    assert.equal(sessionStore.accessToken, "access-2");
    assert.equal(sessionStore.refreshToken, "refresh-2");
    assert.deepEqual(sessionStore.storeContexts, [{ grantType: "refresh_token" }]);
    assert.deepEqual(Object.fromEntries(new URLSearchParams(requestBody)), {
      grant_type: "refresh_token",
      refresh_token: "refresh-1",
      client_id: "neko-web",
    });
  });

  it("coordinates two client instances sharing one rotating token family", async () => {
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "access-1";
    sessionStore.refreshToken = "refresh-1";
    let tail: Promise<unknown> = Promise.resolve();
    const refreshCoordinator = {
      runExclusive<T>(task: () => Promise<T>) {
        const result = tail.then(task, task);
        tail = result.then(() => undefined, () => undefined);
        return result;
      },
    };
    let fetchCount = 0;
    const makeClient = () => createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage: new MemoryStorage(),
      refreshCoordinator,
      navigation: { assign: () => undefined },
      runtime: {
        fetch: async () => {
          fetchCount += 1;
          await new Promise((resolve) => setTimeout(resolve, 5));
          return Response.json({ access_token: "access-2", refresh_token: "refresh-2" });
        },
      },
    });
    const firstClient = makeClient();
    const secondClient = makeClient();

    const [first, second] = await Promise.all([
      firstClient.refreshAccessToken(),
      secondClient.refreshAccessToken(),
    ]);

    assert.equal(first, "access-2");
    assert.equal(second, "access-2");
    assert.equal(fetchCount, 1);
    assert.equal(sessionStore.refreshToken, "refresh-2");
    assert.equal(sessionStore.clearCount, 0);
  });

  it("keeps the existing refresh token when Hydra does not rotate it", async () => {
    const transactionStorage = new MemoryStorage();
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "access-1";
    sessionStore.refreshToken = "refresh-1";
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage,
      navigation: { assign: () => undefined },
      runtime: {
        fetch: async () => Response.json({ access_token: "access-2" }),
      },
    });

    assert.equal(await auth.refreshAccessToken(), "access-2");
    assert.equal(sessionStore.accessToken, "access-2");
    assert.equal(sessionStore.refreshToken, "refresh-1");
  });

  it("preserves the session and rejects transient refresh failures when opted in", async () => {
    for (const status of [429, 500, 503]) {
      const transactionStorage = new MemoryStorage();
      const sessionStore = new MemorySessionStore();
      sessionStore.accessToken = "access-1";
      sessionStore.refreshToken = "refresh-1";
      const auth = createBrowserAuthClient({
        authorizationServerUrl: "https://auth.neko.test",
        clientId: "neko-web",
        redirectUri: "https://app.neko.test/oauth/callback",
        scopes: "openid profile offline",
        sessionStore,
        transactionStorage,
        preserveSessionOnServerError: true,
        navigation: { assign: () => undefined },
        runtime: {
          fetch: async () => new Response("temporarily unavailable", { status }),
        },
      });

      await assert.rejects(() => auth.refreshAccessToken(), new RegExp(String(status)));
      assert.equal(sessionStore.accessToken, "access-1");
      assert.equal(sessionStore.refreshToken, "refresh-1");
      assert.equal(sessionStore.clearCount, 0);
    }
  });

  it("preserves refresh sessions for every non-definitive failure in safe mode", async () => {
    const failures = [
      { status: 400, error: "invalid_request" },
      { status: 408, error: "temporarily_unavailable" },
      { status: 429, error: "slow_down" },
      { status: 500, error: "server_error" },
      { status: 503, error: "temporarily_unavailable" },
    ];
    for (const failure of failures) {
      const sessionStore = new MemorySessionStore();
      sessionStore.accessToken = "access-1";
      sessionStore.refreshToken = "refresh-1";
      const auth = createBrowserAuthClient({
        authorizationServerUrl: "https://auth.neko.test",
        clientId: "neko-web",
        redirectUri: "https://app.neko.test/oauth/callback",
        scopes: "openid profile offline",
        sessionStore,
        transactionStorage: new MemoryStorage(),
        preserveSessionOnRefreshError: true,
        navigation: { assign: () => undefined },
        runtime: {
          fetch: async () => Response.json(
            { error: failure.error },
            { status: failure.status },
          ),
        },
      });

      await assert.rejects(() => auth.refreshAccessToken(), new RegExp(String(failure.status)));
      assert.equal(sessionStore.accessToken, "access-1");
      assert.equal(sessionStore.refreshToken, "refresh-1");
      assert.equal(sessionStore.clearCount, 0);
    }
  });

  it("only clears explicit refresh credential failures in safe mode", async () => {
    for (const oauthError of ["invalid_grant", "invalid_client", "unauthorized_client"]) {
      const sessionStore = new MemorySessionStore();
      sessionStore.accessToken = "access-1";
      sessionStore.refreshToken = "refresh-1";
      const auth = createBrowserAuthClient({
        authorizationServerUrl: "https://auth.neko.test",
        clientId: "neko-web",
        redirectUri: "https://app.neko.test/oauth/callback",
        scopes: "openid profile offline",
        sessionStore,
        transactionStorage: new MemoryStorage(),
        preserveSessionOnRefreshError: true,
        navigation: { assign: () => undefined },
        runtime: {
          fetch: async () => Response.json({ error: oauthError }, { status: 400 }),
        },
      });

      assert.equal(await auth.refreshAccessToken(), null);
      assert.equal(sessionStore.accessToken, null);
      assert.equal(sessionStore.refreshToken, null);
      assert.equal(sessionStore.clearCount, 1);
    }
  });

  it("preserves the refresh session when a successful response is malformed in safe mode", async () => {
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "access-1";
    sessionStore.refreshToken = "refresh-1";
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage: new MemoryStorage(),
      preserveSessionOnRefreshError: true,
      navigation: { assign: () => undefined },
      runtime: { fetch: async () => Response.json({ token_type: "bearer" }) },
    });

    await assert.rejects(() => auth.refreshAccessToken(), /access_token/);
    assert.equal(sessionStore.accessToken, "access-1");
    assert.equal(sessionStore.refreshToken, "refresh-1");
    assert.equal(sessionStore.clearCount, 0);
  });

  it("preserves the session on refresh network errors", async () => {
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "access-1";
    sessionStore.refreshToken = "refresh-1";
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage: new MemoryStorage(),
      preserveSessionOnServerError: true,
      navigation: { assign: () => undefined },
      runtime: {
        fetch: async () => { throw new TypeError("network unavailable"); },
      },
    });

    await assert.rejects(() => auth.refreshAccessToken(), /network unavailable/);
    assert.equal(sessionStore.accessToken, "access-1");
    assert.equal(sessionStore.refreshToken, "refresh-1");
    assert.equal(sessionStore.clearCount, 0);
  });

  it("bounds a hung refresh request and releases its coordinator", async () => {
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "access-1";
    sessionStore.refreshToken = "refresh-1";
    let tail: Promise<unknown> = Promise.resolve();
    const refreshCoordinator = {
      runExclusive<T>(task: () => Promise<T>) {
        const result = tail.then(task, task);
        tail = result.then(() => undefined, () => undefined);
        return result;
      },
    };
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage: new MemoryStorage(),
      preserveSessionOnRefreshError: true,
      oauthRequestTimeoutMs: 10,
      refreshCoordinator,
      navigation: { assign: () => undefined },
      runtime: {
        fetch: async () => new Promise<Response>(() => undefined),
      },
    });

    await Promise.race([
      assert.rejects(
        () => auth.refreshAccessToken(),
        (error: Error) => error.name === "TimeoutError",
      ),
      new Promise<never>((_resolve, reject) => {
        setTimeout(() => reject(new Error("refresh timeout was not honored")), 250);
      }),
    ]);
    assert.equal(sessionStore.accessToken, "access-1");
    assert.equal(sessionStore.refreshToken, "refresh-1");
    assert.equal(sessionStore.clearCount, 0);
    assert.equal(
      await refreshCoordinator.runExclusive(async () => "coordinator-released"),
      "coordinator-released",
    );
  });

  it("bounds a hung refresh response body and preserves its token family", async () => {
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "access-1";
    sessionStore.refreshToken = "refresh-1";
    let tail: Promise<unknown> = Promise.resolve();
    const refreshCoordinator = {
      runExclusive<T>(task: () => Promise<T>) {
        const result = tail.then(task, task);
        tail = result.then(() => undefined, () => undefined);
        return result;
      },
    };
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage: new MemoryStorage(),
      preserveSessionOnRefreshError: true,
      oauthRequestTimeoutMs: 10,
      refreshCoordinator,
      navigation: { assign: () => undefined },
      runtime: { fetch: async () => hangingBodyResponse() },
    });

    await assert.rejects(
      () => auth.refreshAccessToken(),
      (error: Error) => error.name === "TimeoutError",
    );
    assert.equal(sessionStore.accessToken, "access-1");
    assert.equal(sessionStore.refreshToken, "refresh-1");
    assert.equal(sessionStore.clearCount, 0);
    assert.equal(
      await refreshCoordinator.runExclusive(async () => "coordinator-released"),
      "coordinator-released",
    );
  });

  it("keeps browser-auth-v1 server-error clearing by default", async () => {
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "access-1";
    sessionStore.refreshToken = "refresh-1";
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage: new MemoryStorage(),
      navigation: { assign: () => undefined },
      runtime: { fetch: async () => new Response("unavailable", { status: 503 }) },
    });

    assert.equal(await auth.refreshAccessToken(), null);
    assert.equal(sessionStore.accessToken, null);
    assert.equal(sessionStore.refreshToken, null);
    assert.equal(sessionStore.clearCount, 1);
  });

  it("still clears deterministic refresh 4xx responses when preservation is enabled", async () => {
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "access-1";
    sessionStore.refreshToken = "refresh-1";
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage: new MemoryStorage(),
      preserveSessionOnServerError: true,
      navigation: { assign: () => undefined },
      runtime: {
        fetch: async () => Response.json({ error: "invalid_grant" }, { status: 400 }),
      },
    });

    assert.equal(await auth.refreshAccessToken(), null);
    assert.equal(sessionStore.clearCount, 1);
  });

  it("does not let an old refresh response overwrite a replacement account", async () => {
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "account-a-access";
    sessionStore.refreshToken = "account-a-refresh";
    let releaseResponse!: () => void;
    const responseReady = new Promise<void>((resolve) => { releaseResponse = resolve; });
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage: new MemoryStorage(),
      navigation: { assign: () => undefined },
      runtime: {
        fetch: async () => {
          await responseReady;
          return Response.json({
            access_token: "stale-account-a-access",
            refresh_token: "stale-account-a-refresh",
          });
        },
      },
    });

    const refresh = auth.refreshAccessToken();
    sessionStore.accessToken = "account-b-access";
    sessionStore.refreshToken = "account-b-refresh";
    releaseResponse();

    assert.equal(await refresh, "account-b-access");
    assert.equal(sessionStore.accessToken, "account-b-access");
    assert.equal(sessionStore.refreshToken, "account-b-refresh");
    assert.equal(sessionStore.clearCount, 0);
  });

  it("does not let an old failed refresh clear a replacement account", async () => {
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "account-a-access";
    sessionStore.refreshToken = "account-a-refresh";
    let releaseResponse!: () => void;
    const responseReady = new Promise<void>((resolve) => { releaseResponse = resolve; });
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage: new MemoryStorage(),
      navigation: { assign: () => undefined },
      runtime: {
        fetch: async () => {
          await responseReady;
          return Response.json({ error: "invalid_grant" }, { status: 400 });
        },
      },
    });

    const refresh = auth.refreshAccessToken();
    sessionStore.accessToken = "account-b-access";
    sessionStore.refreshToken = "account-b-refresh";
    releaseResponse();

    assert.equal(await refresh, null);
    assert.equal(sessionStore.accessToken, "account-b-access");
    assert.equal(sessionStore.refreshToken, "account-b-refresh");
    assert.equal(sessionStore.clearCount, 0);
  });

  it("cancels a state-bound authorization and returns its continuation", () => {
    const transactionStorage = new MemoryStorage();
    transactionStorage.setItem("state", "state-1");
    transactionStorage.setItem("verifier", "verifier-1");
    transactionStorage.setItem("next", "/stale");
    transactionStorage.setItem("tx:state-1", JSON.stringify({
      verifier: "verifier-1",
      next: "/plugins/42",
      createdAt: 123_456,
    }));
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore: unusedSessionStore(),
      transactionStorage,
      transactionKeys: { state: "state", verifier: "verifier", continuation: "next", prefix: "tx:" },
      navigation: { assign: () => undefined },
    });

    const result = auth.cancelAuthorization("?error=access_denied&state=state-1");

    assert.deepEqual(result, { continuation: "/plugins/42" });
    assert.equal(transactionStorage.length, 0);
  });

  it("rejects a forged error callback without clearing the real transaction", () => {
    const transactionStorage = new MemoryStorage();
    transactionStorage.setItem("state", "real-state");
    transactionStorage.setItem("verifier", "real-verifier");
    transactionStorage.setItem("next", "/settings");
    transactionStorage.setItem("tx:real-state", JSON.stringify({
      verifier: "real-verifier",
      next: "/settings",
      createdAt: 123_456,
    }));
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore: unusedSessionStore(),
      transactionStorage,
      transactionKeys: { state: "state", verifier: "verifier", continuation: "next", prefix: "tx:" },
      navigation: { assign: () => undefined },
    });

    assert.throws(
      () => auth.cancelAuthorization("?error=access_denied&state=forged-state"),
      /state mismatch/,
    );
    assert.equal(transactionStorage.getItem("state"), "real-state");
    assert.ok(transactionStorage.getItem("tx:real-state"));
  });

  it("clears locally before best-effort revocation and cannot clear a replacement session", async () => {
    const transactionStorage = new MemoryStorage();
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "account-a-access";
    sessionStore.refreshToken = "account-a-refresh";
    let releaseRevocations!: () => void;
    const revocationsReleased = new Promise<void>((resolve) => { releaseRevocations = resolve; });
    let revokeCount = 0;
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage,
      localFirstRevoke: true,
      revokeTimeoutMs: 1_000,
      navigation: { assign: () => undefined },
      runtime: {
        fetch: async () => {
          revokeCount += 1;
          await revocationsReleased;
          return new Response(null, { status: 200 });
        },
      },
    });

    const revoke = auth.revokeSession();
    assert.equal(sessionStore.accessToken, null);
    assert.equal(sessionStore.refreshToken, null);
    assert.equal(sessionStore.clearCount, 1);

    sessionStore.accessToken = "account-b-access";
    sessionStore.refreshToken = "account-b-refresh";
    releaseRevocations();
    await revoke;

    assert.equal(revokeCount, 2);
    assert.equal(sessionStore.accessToken, "account-b-access");
    assert.equal(sessionStore.refreshToken, "account-b-refresh");
    assert.equal(sessionStore.clearCount, 1);
  });

  it("revokes detached tokens without reading or clearing the current session", async () => {
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "account-b-access";
    sessionStore.refreshToken = "account-b-refresh";
    const revoked: string[] = [];
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage: new MemoryStorage(),
      localFirstRevoke: true,
      revokeTimeoutMs: 100,
      navigation: { assign: () => undefined },
      runtime: {
        fetch: async (_input, init) => {
          revoked.push(new URLSearchParams(String(init?.body)).get("token") ?? "");
          return new Response(null, { status: 200 });
        },
      },
    });

    await auth.revokeTokens({
      accessToken: "detached-account-a-access",
      refreshToken: "detached-account-a-refresh",
    });

    assert.deepEqual(revoked.sort(), [
      "detached-account-a-access",
      "detached-account-a-refresh",
    ]);
    assert.equal(sessionStore.accessToken, "account-b-access");
    assert.equal(sessionStore.refreshToken, "account-b-refresh");
    assert.equal(sessionStore.clearCount, 0);
  });

  it("bounds local-first best-effort revocation even when fetch ignores abort", async () => {
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "access-1";
    sessionStore.refreshToken = "refresh-1";
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage: new MemoryStorage(),
      localFirstRevoke: true,
      revokeTimeoutMs: 10,
      navigation: { assign: () => undefined },
      runtime: {
        fetch: async () => new Promise<Response>(() => undefined),
      },
    });

    await Promise.race([
      auth.revokeSession(),
      new Promise<never>((_resolve, reject) => {
        setTimeout(() => reject(new Error("revokeSession did not honor its timeout")), 250);
      }),
    ]);
    assert.equal(sessionStore.clearCount, 1);
  });

  it("revokes available tokens and always clears local and transient state", async () => {
    const transactionStorage = new MemoryStorage();
    const sessionStore = new MemorySessionStore();
    sessionStore.accessToken = "access-1";
    sessionStore.refreshToken = "refresh-1";
    transactionStorage.setItem("state", "state-1");
    transactionStorage.setItem("verifier", "verifier-1");
    transactionStorage.setItem("next", "/plugins");
    transactionStorage.setItem("tx:state-1", "{}");
    const revokeBodies: string[] = [];
    let changedCount = 0;
    const auth = createBrowserAuthClient({
      authorizationServerUrl: "https://auth.neko.test",
      clientId: "neko-web",
      redirectUri: "https://app.neko.test/oauth/callback",
      scopes: "openid profile offline",
      sessionStore,
      transactionStorage,
      transactionKeys: { state: "state", verifier: "verifier", continuation: "next", prefix: "tx:" },
      navigation: { assign: () => undefined },
      onSessionChanged: () => { changedCount += 1; },
      runtime: {
        fetch: async (input, init) => {
          assert.equal(input, "https://auth.neko.test/oauth2/revoke");
          revokeBodies.push(String(init?.body));
          return new Response("unavailable", { status: 503 });
        },
      },
    });

    assert.equal(auth.getAccessToken(), "access-1");
    await auth.revokeSession();

    assert.equal(revokeBodies.length, 2);
    assert.deepEqual(
      revokeBodies.map((body) => new URLSearchParams(body).get("token_type_hint")).sort(),
      ["access_token", "refresh_token"],
    );
    assert.ok(revokeBodies.every(
      (body) => new URLSearchParams(body).get("client_id") === "neko-web",
    ));
    assert.equal(sessionStore.accessToken, null);
    assert.equal(sessionStore.refreshToken, null);
    assert.equal(sessionStore.clearCount, 1);
    assert.equal(transactionStorage.length, 0);
    assert.equal(changedCount, 1);
  });
});
