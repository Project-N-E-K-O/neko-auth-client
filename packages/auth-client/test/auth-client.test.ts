import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createBrowserAuthClient,
  type AuthSessionStore,
  type StorageLike,
  type TokenResponse,
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

class MemorySessionStore implements AuthSessionStore {
  accessToken: string | null = null;
  refreshToken: string | null = null;
  clearCount = 0;

  getAccessToken() {
    return this.accessToken;
  }

  getRefreshToken() {
    return this.refreshToken;
  }

  storeTokens(token: TokenResponse) {
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
    assert.deepEqual(Object.fromEntries(new URLSearchParams(requestBody)), {
      grant_type: "refresh_token",
      refresh_token: "refresh-1",
      client_id: "neko-web",
    });
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
