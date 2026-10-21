// Every route refuses a request without a valid token (roadmap P0 exit criterion).
//
// The routes are read from the app itself, not from a list kept by hand, so a
// route added tomorrow is covered tomorrow. Runs without a database: the token
// check comes before any query.

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");

process.env.DATABASE_URL ||= "postgres://unused@127.0.0.1:1/unused";
process.env.AUTH_ENFORCEMENT = "on";
process.env.AUTH_JWT_SECRET ||= "route-test-secret-0123456789-0123456789";

const { loadAppWithRoutes, concrete } = require("./support/routes");
const { isPublic } = require("../middleware/auth");

const { app, routes } = loadAppWithRoutes();

// Reachable without a token, and why. Adding to this list is a security decision.
const PUBLIC = new Set([
  "GET /", // health check
  "POST /auth/login",
  "POST /auth/microsoft", // checks Microsoft's signature itself
  "POST /auth/forgot-password", // same answer whether or not the email exists
  "GET /auth/reset-password/:token", // the emailed token is the credential
  "POST /auth/reset-password",
  "POST /integrations/askmira/organizations", // AskMira's signed assertion, checked in the route
  "POST /integrations/askmira/users/sync",
  "POST /integrations/askmira/query", // read-only, same signed assertion (use=query)
  "POST /integrations/askmira/connect/token", // one-time code + PKCE verifier, checked in the route
  "POST /integrations/askmira/connect/revoke", // signed with the workspace's own secret (use=revoke)
  "POST /auth/askmira/exchange", // one-time AskMira launch token, checked in the route
]);

let server;
let base;

before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

function call(route, headers = {}) {
  const hasBody = !["GET", "DELETE"].includes(route.method);
  return fetch(base + concrete(route.path), {
    method: route.method,
    headers: { "Content-Type": "application/json", ...headers },
    body: hasBody ? "{}" : undefined,
  });
}

test("the app registers the routes we expect to check", () => {
  assert.ok(routes.length > 50, `only ${routes.length} routes found — is the route collector broken?`);
  for (const key of PUBLIC) {
    assert.ok(
      routes.some((r) => `${r.method} ${r.path}` === key),
      `${key} is declared public here but the app has no such route`,
    );
  }
});

test("only the declared routes are public", () => {
  const actual = routes
    .filter((r) => isPublic({ method: r.method, path: concrete(r.path) }))
    .map((r) => `${r.method} ${r.path}`);
  assert.deepEqual(new Set(actual), PUBLIC);
});

test("every other route answers 401 without a token", async () => {
  const leaks = [];
  for (const route of routes) {
    if (PUBLIC.has(`${route.method} ${route.path}`)) continue;
    const response = await call(route);
    if (response.status !== 401) leaks.push(`${route.method} ${route.path} → ${response.status}`);
  }
  assert.deepEqual(leaks, []);
});

test("every other route answers 401 with a forged or malformed token", async () => {
  const forged =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
    Buffer.from(JSON.stringify({ sub: "sa@platform.com", role: "super_admin" })).toString("base64url") +
    ".c2lnbmF0dXJl";
  const leaks = [];
  for (const route of routes) {
    if (PUBLIC.has(`${route.method} ${route.path}`)) continue;
    for (const token of [forged, "not-a-jwt"]) {
      const response = await call(route, { Authorization: `Bearer ${token}` });
      if (response.status !== 401) leaks.push(`${route.method} ${route.path} → ${response.status}`);
    }
  }
  assert.deepEqual(leaks, []);
});

test("an unknown path also needs a token", async () => {
  const response = await fetch(`${base}/no/such/route`);
  assert.equal(response.status, 401);
});
