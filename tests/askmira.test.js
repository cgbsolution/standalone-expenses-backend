// The AskMira link (routes/askmira.js): provisioning, people sync and sign-in.
//
// Tokens are minted here the way AskMira mints them: HS256 with the shared
// secret, aud "askmira:expense", iss "askmira", 60 seconds, and on provisioning
// calls `bh` = SHA-256 of the exact body.

const crypto = require("crypto");
const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const { SignJWT } = require("jose");
const { SKIP, PASSWORD, resetDatabase, seedPeople, startApi } = require("./support/server");

const SECRET = "askmira-expense-secret-0123456789abcdef0123";

function token(use, sub, claims = {}, { secret = SECRET, aud = "askmira:expense" } = {}) {
  return new SignJWT({ use, ...claims })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer("askmira").setAudience(aud).setSubject(sub)
    .setIssuedAt().setExpirationTime("60s").setJti(crypto.randomUUID())
    .sign(new TextEncoder().encode(secret));
}

describe("AskMira link switched off", { skip: SKIP }, () => {
  let db;
  let api;
  before(async () => {
    db = await resetDatabase();
    api = await startApi();
  });
  after(async () => {
    await api?.stop();
    await db?.end();
  });

  test("without ASKMIRA_SHARED_SECRET the endpoints don't exist", async () => {
    const r = await api.call("POST", "/integrations/askmira/organizations", { body: { tenant_id: "t" } });
    assert.equal(r.status, 404);
    assert.equal((await api.call("POST", "/auth/askmira/exchange", { body: { token: "x" } })).status, 404);
  });
});

describe("AskMira link", { skip: SKIP }, () => {
  let db;
  let api;
  const T1 = crypto.randomUUID();
  let repSession;
  const people = [
    { id: "u1", email: "HR@newco.com", name: "HR", role: "admin" },
    { id: "u2", email: "mgr@newco.com", name: "Mgr", role: "employee", department: "Sales", grade: "L5" },
    { id: "u3", email: "rep@newco.com", name: "Rep", role: "employee", manager_email: "mgr@newco.com", employee_code: "E1" },
    { id: "u4", email: "taken@beta.com", name: "Taken", role: "employee" },
    { id: "u5", email: "sa@platform.com", name: "SA", role: "admin" },
    { id: "u6", email: "odd@newco.com", name: "Odd", role: "boss" },
  ];

  before(async () => {
    db = await resetDatabase();
    await seedPeople(db, [
      ["sa@platform.com", "SA", "super_admin", null],
      ["admin@acme.com", "Acme Admin", "admin", "acme"],
      ["emp@acme.com", "Acme Emp", "employee", "acme"],
      ["admin@beta.com", "Beta Admin", "admin", "beta"],
      ["taken@beta.com", "Taken", "employee", "beta"],
    ]);
    await db.query(`INSERT INTO tenant_settings (slug, name, status) VALUES ('acme','Acme','active'), ('beta','Beta','active')`);
    api = await startApi({ ASKMIRA_SHARED_SECRET: SECRET });
  });

  after(async () => {
    await api?.stop();
    await db?.end();
  });

  async function provision(pathname, payload, opts = {}) {
    const body = JSON.stringify(payload);
    const bh = crypto.createHash("sha256").update(body).digest("hex");
    const t = await token("provision", opts.sub || payload.tenant_id, { bh }, opts);
    return api.call("POST", `/integrations/askmira${pathname}`, {
      headers: { Authorization: `Bearer ${t}` },
      body: opts.tamper ? body.replace('"name"', ' "name"') : body,
    });
  }

  const exchange = async (t) => api.call("POST", "/auth/askmira/exchange", { body: { token: t } });
  const launch = (sub, claims) => token("launch", sub, { tid: T1, ext: "newco", role: "employee", ...claims });

  test("forged, misdirected or tampered assertions are refused", async () => {
    const company = { tenant_id: T1, name: "NewCo", slug: "newco", domain: null };
    assert.equal((await provision("/organizations", company, { secret: "y".repeat(40) })).status, 401);
    assert.equal((await provision("/organizations", company, { aud: "askmira:interview" })).status, 401);
    assert.equal((await provision("/organizations", company, { tamper: true })).status, 401);
    assert.equal((await provision("/organizations", company, { sub: crypto.randomUUID() })).status, 401);
  });

  test("organizations: created once, adopted by domain, never stolen", async () => {
    const company = { tenant_id: T1, name: "NewCo", slug: "newco", domain: null };
    const created = await provision("/organizations", company);
    assert.equal(created.data.external_ref, "newco");
    assert.equal((await provision("/organizations", company)).data.external_ref, "newco");
    const { rows } = await db.query(`SELECT status FROM tenant_settings WHERE slug = 'newco'`);
    assert.equal(rows[0].status, "active");

    const clash = await provision("/organizations", { tenant_id: crypto.randomUUID(), name: "Beta 2", slug: "beta", domain: "nomatch.com" });
    assert.equal(clash.data.external_ref, "beta-2", "a taken slug gets a free one");

    const adopt = await provision("/organizations", { tenant_id: crypto.randomUUID(), name: "Acme", slug: "acme-x", domain: "acme.com" });
    assert.equal(adopt.data.external_ref, "acme");
    assert.equal(adopt.data.adopted, true);
    const steal = await provision("/organizations", { tenant_id: crypto.randomUUID(), name: "Acme", slug: "acme-y", domain: "acme.com" });
    assert.equal(steal.status, 409);
  });

  test("people sync adds, skips and leaves people added here alone", async () => {
    const sync = await provision("/users/sync", { tenant_id: T1, complete: true, users: people });
    assert.equal(sync.status, 200);
    assert.equal(sync.data.created, 3);
    assert.deepEqual(sync.data.skipped.map((s) => s.email).sort(), ["odd@newco.com", "sa@platform.com", "taken@beta.com"]);
    const { rows: [rep] } = await db.query(`SELECT * FROM employees WHERE email = 'rep@newco.com'`);
    assert.equal(rep.tenant, "newco");
    assert.equal(rep.manager_email, "mgr@newco.com");
    assert.equal(rep.employee_id, "E1");
    assert.equal(rep.askmira_user_id, "u3");

    await db.query(`INSERT INTO employees (email, name, role, tenant) VALUES ('native@newco.com','Native','employee','newco')`);
    const again = await provision("/users/sync", { tenant_id: T1, complete: true, users: people });
    assert.deepEqual([again.data.created, again.data.updated, again.data.deactivated], [0, 0, 0]);
  });

  test("a launch link signs in once", async () => {
    const t = await launch("u3", { email: "rep@newco.com", name: "Rep" });
    const ok = await exchange(t);
    assert.equal(ok.status, 200);
    assert.equal(ok.data.user.tenant, "newco");
    assert.equal((await api.call("GET", "/auth/me", { token: ok.data.token })).data.user.email, "rep@newco.com");
    assert.equal((await exchange(t)).status, 401, "a second use is refused");
    repSession = ok.data.token;
  });

  test("a leaver loses access everywhere at once", async () => {
    const sync = await provision("/users/sync", { tenant_id: T1, complete: true, users: people.filter((p) => p.id !== "u3") });
    assert.equal(sync.data.deactivated, 1);
    const { rows: [native] } = await db.query(`SELECT deactivated_at FROM employees WHERE email = 'native@newco.com'`);
    assert.equal(native.deactivated_at, null, "people added in ExpGenie are never switched off by AskMira");
    assert.equal((await api.call("GET", "/auth/me", { token: repSession })).status, 401);
    assert.equal((await exchange(await launch("u3", { email: "rep@newco.com" }))).status, 403);
    await db.query(`UPDATE employees SET password_hash = $1 WHERE email = 'rep@newco.com'`, [await bcrypt.hash(PASSWORD, 4)]);
    const pw = await api.call("POST", "/auth/login", { body: { email: "rep@newco.com", password: PASSWORD } });
    assert.equal(pw.status, 403, "nor with a password");

    const back = await provision("/users/sync", { tenant_id: T1, complete: true, users: people });
    assert.ok(back.data.updated >= 1, "back in the roster, switched on again");
  });

  test("launch links can't be bent", async () => {
    const joiner = await exchange(await launch("u9", { email: "new@newco.com", name: "New" }));
    assert.equal(joiner.status, 200, "a joiner since the last sync gets in");
    assert.equal(joiner.data.user.email, "new@newco.com");

    assert.equal((await exchange(await launch("u9", { email: "admin@beta.com", role: "admin" }))).status, 409, "another workspace's account");
    assert.equal((await exchange(await token("launch", "u9", { tid: crypto.randomUUID(), email: "x@newco.com", role: "employee" }))).status, 403, "unlinked workspace");
    assert.equal((await exchange(await launch("u9", { ext: "beta", email: "x@newco.com" }))).status, 403, "wrong tenant reference");
    assert.equal((await exchange(await token("launch", "u9", { tid: T1, ext: "newco", email: "x@newco.com", role: "admin" }, { secret: "z".repeat(40) }))).status, 401, "forged");
    assert.equal((await exchange(await token("provision", "u9", { tid: T1, ext: "newco", email: "x@newco.com", role: "admin" }))).status, 401, "wrong token kind");
  });
});

// Ask Mira's read-only questions (POST /integrations/askmira/query).
describe("AskMira queries", { skip: SKIP }, () => {
  let db;
  let api;
  const T1 = crypto.randomUUID();
  const T2 = crypto.randomUUID();
  const actor = (email, role = "employee") => ({ id: crypto.randomUUID(), email, role });
  const hr = actor("hr@newco.com", "admin");
  const mgr = actor("mgr@newco.com");
  const rep = actor("rep@newco.com");

  async function ask(kind, who, params = {}, opts = {}) {
    const payload = { tenant_id: opts.tenant || T1, actor: who, kind, params };
    const body = JSON.stringify(payload);
    const bh = crypto.createHash("sha256").update(body).digest("hex");
    const t = await token(opts.use || "query", opts.sub || payload.tenant_id, { bh });
    return api.call("POST", "/integrations/askmira/query", {
      headers: { Authorization: `Bearer ${t}` },
      body,
    });
  }

  async function provision(pathname, payload) {
    const body = JSON.stringify(payload);
    const bh = crypto.createHash("sha256").update(body).digest("hex");
    const t = await token("provision", payload.tenant_id, { bh });
    return api.call("POST", `/integrations/askmira${pathname}`, { headers: { Authorization: `Bearer ${t}` }, body });
  }

  async function claim(id, submitter, name, approver, status, data, daysAgo = 0) {
    await db.query(
      `INSERT INTO expenses (id, user_id, unique_key, approver_email, submitter_email, submitter_name,
                             approval_status, data, created_at, updated_at)
       VALUES ($1, $2, $1, $3, $2, $4, $5, $6, now() - make_interval(days => $7::int), now())`,
      [id, submitter, approver, name, status, data, daysAgo],
    );
  }

  before(async () => {
    db = await resetDatabase();
    await seedPeople(db, [
      ["admin@beta.com", "Beta Admin", "admin", "beta"],
      ["emp@beta.com", "Beta Emp", "employee", "beta"],
    ]);
    await db.query(`INSERT INTO tenant_settings (slug, name, status) VALUES ('beta','Beta','active')`);
    api = await startApi({ ASKMIRA_SHARED_SECRET: SECRET });

    assert.equal((await provision("/organizations", { tenant_id: T1, name: "NewCo", slug: "newco", domain: null })).status, 200);
    assert.equal((await provision("/organizations", { tenant_id: T2, name: "Beta", slug: "beta-x", domain: "beta.com" })).data.external_ref, "beta");
    await seedPeople(db, [
      ["hr@newco.com", "HR", "admin", "newco"],
      ["mgr@newco.com", "Mgr", "employee", "newco", "hr@newco.com"],
      ["rep@newco.com", "Rep", "employee", "newco", "mgr@newco.com"],
      ["gone@newco.com", "Gone", "employee", "newco", "mgr@newco.com"],
    ]);
    await db.query(`UPDATE employees SET deactivated_at = now() WHERE email = 'gone@newco.com'`);

    // A comma-formatted total, as some paths write it.
    await claim("c1", "rep@newco.com", "Rep", "mgr@newco.com", "Pending", {
      ExpenseTitle: "Client lunch", TotalAmount: "1,250.50",
      ExpenseData: [{ InvoiceAmount: 1250.5, Category: "Meals" }],
    });
    // No total: the lines are added up. The chatbot's status variant and its ExpenseType.
    await claim("c2", "rep@newco.com", "Rep", "hr@newco.com", "ApprovedByFinance", {
      ExpenseTitle: "Cab rides",
      ExpenseData: [{ InvoiceAmount: 300, ExpenseType: "Travel" }, { InvoiceAmount: "200.25", ExpenseType: "Travel" }],
    });
    await claim("c3", "mgr@newco.com", "", "hr@newco.com", "Approved", {
      ExpenseTitle: "Hotel", TotalAmount: 4000, PaymentStatus: "Paid",
      ExpenseData: [{ InvoiceAmount: 4000, Category: "Lodging" }],
    });
    await claim("c4", "rep@newco.com", "Rep", "mgr@newco.com", "Draft", {
      ExpenseTitle: "Old draft", TotalAmount: 99, ExpenseData: [],
    }, 60);
    await claim("b1", "emp@beta.com", "Beta Emp", "admin@beta.com", "Pending", {
      ExpenseTitle: "Beta secret", TotalAmount: 99999, ExpenseData: [{ Category: "Secret" }],
    });
  });

  after(async () => {
    await api?.stop();
    await db?.end();
  });

  test("a person sees their own claims, amounts read as the dashboard reads them", async () => {
    const r = await ask("claims", rep, { scope: "mine" });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.equal(r.data.kind, "claims");
    assert.equal(r.data.scope, "mine");
    assert.equal(r.data.total, 3);
    const byRef = Object.fromEntries(r.data.claims.map((c) => [c.reference, c]));
    assert.deepEqual(Object.keys(byRef).sort(), ["c1", "c2", "c4"]);
    assert.equal(byRef.c1.amount, "1250.50");
    assert.equal(byRef.c1.category, "Meals");
    assert.equal(byRef.c2.amount, "500.25");
    assert.equal(byRef.c2.status, "Approved");
    assert.equal(byRef.c2.category, "Travel");
    assert.equal(byRef.c2.currency, "INR");
    assert.equal(typeof byRef.c2.amount, "string", "money never travels as a float");
  });

  test("approvals: what waits on the approver now", async () => {
    const r = await ask("claims", mgr, { scope: "approvals", status: "pending" });
    assert.deepEqual(r.data.claims.map((c) => c.reference), ["c1"]);
    assert.equal(r.data.claims[0].submitter, "Rep");
  });

  test("company: an admin's, and never another tenant's", async () => {
    const r = await ask("claims", hr, { scope: "company" });
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.claims.map((c) => c.reference).sort(), ["c1", "c2", "c3", "c4"]);
    assert.equal(r.data.claims.find((c) => c.reference === "c3").submitter, "Mgr", "the name on record when the claim has none");
    assert.ok(!JSON.stringify(r.data).includes("Beta secret"));

    assert.equal((await ask("claims", rep, { scope: "company" })).status, 403, "an employee");
    assert.equal((await ask("claims", { ...hr, role: "employee" }, { scope: "company" })).status, 403, "AskMira must say admin too");
    const beta = await ask("claims", actor("admin@beta.com", "admin"), { scope: "company" }, { tenant: T2 });
    assert.deepEqual(beta.data.claims.map((c) => c.reference), ["b1"]);
  });

  test("summary adds up in numeric, by status, category and unpaid", async () => {
    const r = await ask("summary", hr, { scope: "company" });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    const status = Object.fromEntries(r.data.by_status.map((row) => [row.status, row]));
    assert.equal(status.Approved.count, 2);
    assert.equal(status.Approved.amount, "4500.25");
    assert.equal(status.Pending.amount, "1250.50");
    assert.equal(status.Draft.count, 1);
    assert.equal(r.data.by_category[0].category, "Lodging");
    assert.deepEqual(r.data.approved_unpaid, [{ currency: "INR", count: 1, amount: "500.25" }]);

    const mine = await ask("summary", rep, { scope: "mine", status: "approved" });
    assert.deepEqual(mine.data.by_status.map((row) => [row.status, row.amount]), [["Approved", "500.25"]]);
  });

  test("a window and a search narrow it; wildcards are literal", async () => {
    const now = Date.now();
    const window = { scope: "mine", from: new Date(now - 7 * 864e5).toISOString(), to: new Date(now + 864e5).toISOString() };
    assert.equal((await ask("claims", rep, window)).data.total, 2, "the 60-day-old draft is outside");
    assert.equal((await ask("claims", rep, { scope: "mine", query: "cab" })).data.total, 1);
    assert.equal((await ask("claims", rep, { scope: "mine", query: "%" })).data.total, 0);
    const tooLong = { scope: "mine", from: "2026-01-01T00:00:00Z", to: "2026-12-31T00:00:00Z" };
    assert.equal((await ask("claims", rep, tooLong)).status, 422);
  });

  test("strangers, leavers, other workspaces and other tokens are refused", async () => {
    assert.equal((await ask("claims", rep, { scope: "mine" }, { use: "provision" })).status, 401);
    assert.equal((await ask("claims", rep, { scope: "mine" }, { use: "launch" })).status, 401);
    assert.equal((await ask("claims", rep, { scope: "mine" }, { sub: T2 })).status, 401, "token for another workspace");
    assert.equal((await ask("claims", actor("admin@beta.com", "admin"), { scope: "company" })).status, 403, "another tenant's admin");
    assert.equal((await ask("claims", actor("nobody@newco.com"), { scope: "mine" })).status, 403);
    assert.equal((await ask("claims", actor("gone@newco.com"), { scope: "mine" })).status, 403, "switched off");
    assert.equal((await ask("claims", { ...rep, role: "boss" }, { scope: "mine" })).status, 403);
    assert.equal((await ask("claims", rep, { scope: "mine" }, { tenant: crypto.randomUUID() })).status, 404);
    assert.equal((await ask("salaries", rep, {})).status, 422);
    assert.equal((await ask("claims", rep, { scope: "everyone" })).status, 422);
  });
});

describe("AskMira Connectors: a workspace admin connects from AskMira", { skip: SKIP }, () => {
  let db;
  let api;
  let adminToken;
  let empToken;
  let superToken;
  const CALLBACK = "https://askmira.test/settings/connectors/callback";

  before(async () => {
    db = await resetDatabase();
    await seedPeople(db, [
      ["sa@platform.com", "SA", "super_admin", null],
      ["admin@acme.com", "Acme Admin", "admin", "acme"],
      ["emp@acme.com", "Acme Emp", "employee", "acme"],
      ["admin@beta.com", "Beta Admin", "admin", "beta"],
    ]);
    await db.query(`INSERT INTO tenant_settings (slug, name, status) VALUES ('acme','Acme','active'), ('beta','Beta','active')`);
    api = await startApi(); // no ASKMIRA_SHARED_SECRET: only per-workspace connections
    const login = async (email) =>
      (await api.call("POST", "/auth/login", { body: { email, password: PASSWORD } })).data.token;
    adminToken = await login("admin@acme.com");
    empToken = await login("emp@acme.com");
    superToken = await login("sa@platform.com");
  });

  after(async () => {
    await api?.stop();
    await db?.end();
  });

  const pkce = () => {
    const verifier = crypto.randomBytes(48).toString("base64url");
    return { verifier, challenge: crypto.createHash("sha256").update(verifier).digest("base64url") };
  };
  const approve = (tok, tenant, challenge, redirect_uri = CALLBACK) =>
    api.call("POST", "/askmira-connection/approve", {
      token: tok,
      body: { tenant_id: tenant, tenant_name: "CGB Solutions", redirect_uri, state: "opaque-state", challenge },
    });
  const codeOf = (r) => new URL(r.data.redirect_to).searchParams.get("code");
  const swap = (code, verifier, tenant_id) =>
    api.call("POST", "/integrations/askmira/connect/token", { body: { code, verifier, tenant_id } });

  async function signed(use, pathname, payload, secret) {
    const body = JSON.stringify(payload);
    const bh = crypto.createHash("sha256").update(body).digest("hex");
    const t = await token(use, payload.tenant_id, { bh }, { secret });
    return api.call("POST", `/integrations/askmira${pathname}`, { headers: { Authorization: `Bearer ${t}` }, body });
  }
  const sync = (tenant, secret) =>
    signed("provision", "/users/sync", { tenant_id: tenant, complete: true, users: [] }, secret);

  test("only a workspace admin may allow, and only towards an AskMira callback", async () => {
    const T = crypto.randomUUID();
    const { challenge } = pkce();
    assert.equal((await approve(empToken, T, challenge)).status, 403);
    assert.equal((await approve(superToken, T, challenge)).status, 403, "a super admin has no workspace to give");
    for (const bad of ["http://askmira.test/settings/connectors/callback", "https://evil.test/steal",
      "https://askmira.test/settings/connectors/callback?x=1"]) {
      assert.equal((await approve(adminToken, T, challenge, bad)).status, 422, bad);
    }
  });

  test("allow → swap → the secret reaches only that workspace; either side disconnects", async () => {
    const T = crypto.randomUUID();
    const other = crypto.randomUUID();
    const { verifier, challenge } = pkce();
    const allowed = await approve(adminToken, T, challenge);
    assert.equal(allowed.status, 200);
    const back = new URL(allowed.data.redirect_to);
    assert.equal(back.origin + back.pathname, CALLBACK);
    assert.equal(back.searchParams.get("state"), "opaque-state");
    const code = codeOf(allowed);

    assert.equal((await swap(code, pkce().verifier, T)).status, 400, "wrong verifier");
    assert.equal((await swap(code, verifier, T)).status, 400, "and the code is spent");

    const again = await approve(adminToken, T, challenge);
    const made = await swap(codeOf(again), verifier, T);
    assert.equal(made.status, 200);
    assert.equal(made.data.external_ref, "acme");
    const secret = made.data.secret;
    const { rows } = await db.query(`SELECT * FROM askmira_links WHERE askmira_tenant_id = $1`, [T]);
    assert.equal(rows[0].slug, "acme");
    assert.ok(!JSON.stringify(rows).includes(secret), "the secret is never stored");

    assert.equal((await sync(T, secret)).status, 200);
    assert.equal((await sync(other, secret)).status, 404, "another workspace: nothing to check it with");
    const status = await api.call("GET", "/askmira-connection", { token: adminToken });
    assert.equal(status.data.connected, true);
    assert.equal(status.data.askmira_origin, "https://askmira.test");

    // Connected to T, Acme can't be given to another AskMira workspace.
    assert.equal((await approve(adminToken, other, challenge)).status, 409);

    // AskMira disconnects: the secret stops working.
    assert.equal((await signed("revoke", "/connect/revoke", { tenant_id: T }, secret)).status, 200);
    assert.equal((await sync(T, secret)).status, 404);

    // Connect again, then disconnect from this side.
    const third = await swap(codeOf(await approve(adminToken, T, challenge)), verifier, T);
    assert.equal((await sync(T, third.data.secret)).status, 200);
    const gone = await api.call("DELETE", "/askmira-connection", { token: adminToken });
    assert.equal(gone.data.connected, false);
    assert.equal((await sync(T, third.data.secret)).status, 404);
  });
});
