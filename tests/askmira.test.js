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

  async function act(kind, who, params = {}, opts = {}) {
    const payload = { tenant_id: opts.tenant || T1, actor: who, kind, params };
    const body = JSON.stringify(payload);
    const bh = crypto.createHash("sha256").update(body).digest("hex");
    const t = opts.token || (await token(opts.use || "act", opts.sub || payload.tenant_id, { bh }));
    return api.call("POST", "/integrations/askmira/act", {
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

  test("summary says who submitted how much, and month by month", async () => {
    const r = await ask("summary", hr, { scope: "company" });
    assert.equal(r.status, 200, api.log().slice(-1200));
    assert.deepEqual(
      r.data.by_submitter.map((row) => [row.submitter, row.email, row.count, row.amount]),
      [["Mgr", "mgr@newco.com", 1, "4000.00"], ["Rep", "rep@newco.com", 3, "1849.75"]],
    );
    const months = r.data.by_month;
    assert.equal(months.reduce((n, row) => n + row.count, 0), 4);
    assert.ok(months.every((row) => /^\d{4}-\d{2}$/.test(row.month)));
    assert.ok(months.some((row) => row.people === 2), "this month: Rep and Mgr");

    // An employee's summary is only ever their own.
    const mine = await ask("summary", rep, { scope: "mine" });
    assert.deepEqual(mine.data.by_submitter.map((row) => row.submitter), ["Rep"]);
    assert.ok(mine.data.by_month.every((row) => row.people === 1));
    assert.ok(!JSON.stringify(mine.data).includes("Mgr"));
  });

  test("payable: approved and unpaid claims, with who submitted them, for an admin only", async () => {
    const r = await ask("payable", hr, { scope: "company" });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.deepEqual(
      r.data.claims.map((c) => [c.reference, c.submitter_email, c.amount]),
      [["c2", "rep@newco.com", "500.25"]],
      "c3 is paid already, c1 pending, c4 a draft, b1 another tenant's",
    );
    assert.equal((await ask("payable", rep, { scope: "mine" })).status, 403);
    assert.equal((await ask("payable", rep, { scope: "company" })).status, 403);
  });

  test("claims.paid records payroll's payment once, and only on this tenant's approved claims", async () => {
    const paid = await act("claims.paid", hr, {
      references: ["c2", "c1", "c3", "b1", "nope"],
      paid_on: "2026-11-30",
      note: "Paid with salary for November 2026",
    });
    assert.equal(paid.status, 200, JSON.stringify(paid.data));
    assert.deepEqual(paid.data.paid, ["c2"]);
    assert.deepEqual(
      Object.fromEntries(paid.data.skipped.map((s) => [s.reference, s.reason])),
      { c1: "Not approved.", c3: "Already paid.", b1: "Not a claim of this workspace.", nope: "Not a claim of this workspace." },
    );
    const { rows } = await db.query(`SELECT data FROM expenses WHERE id = 'c2'`);
    assert.equal(rows[0].data.PaymentStatus, "Paid");
    assert.equal(rows[0].data.PaymentInfo.Method, "AskMira payroll");
    assert.ok(rows[0].data.ApprovalHistory.at(-1).comments.includes("November 2026"));
    assert.deepEqual((await ask("payable", hr, { scope: "company" })).data.claims, []);

    const again = await act("claims.paid", hr, { references: ["c2"], paid_on: "2026-11-30" });
    assert.deepEqual(again.data.paid, []);
    assert.equal(again.data.skipped[0].reason, "Already paid.");
  });

  test("claims.paid is refused for the wrong person, token or replay", async () => {
    const params = { references: ["c1"], paid_on: "2026-11-30" };
    assert.equal((await act("claims.paid", rep, params)).status, 403, "not an admin");
    assert.equal((await act("claims.paid", { ...hr, role: "employee" }, params)).status, 403);
    assert.equal((await act("claims.paid", actor("admin@beta.com", "admin"), params)).status, 403);
    assert.equal((await act("claims.paid", hr, params, { use: "query" })).status, 401);
    assert.equal((await act("claims.paid", hr, { references: [], paid_on: "2026-11-30" })).status, 422);
    assert.equal((await act("claims.paid", hr, { references: ["c1"], paid_on: "soon" })).status, 422);
    assert.equal((await act("refund.everything", hr, params)).status, 422);

    // The same signed request twice: the second is refused.
    const payload = { tenant_id: T1, actor: hr, kind: "claims.paid", params };
    const body = JSON.stringify(payload);
    const bh = crypto.createHash("sha256").update(body).digest("hex");
    const t = await token("act", T1, { bh });
    const send = () => api.call("POST", "/integrations/askmira/act", { headers: { Authorization: `Bearer ${t}` }, body });
    assert.equal((await send()).status, 200);
    assert.equal((await send()).status, 401);
  });

  test("a window and a search narrow it; wildcards are literal", async () => {
    const now = Date.now();
    const window = { scope: "mine", from: new Date(now - 7 * 864e5).toISOString(), to: new Date(now + 864e5).toISOString() };
    assert.equal((await ask("claims", rep, window)).data.total, 2, "the 60-day-old draft is outside");
    assert.equal((await ask("claims", rep, { scope: "mine", query: "cab" })).data.total, 1);
    assert.equal((await ask("claims", rep, { scope: "mine", query: "%" })).data.total, 0);
    const year = { scope: "mine", from: new Date(now - 365 * 864e5).toISOString(), to: new Date(now + 864e5).toISOString() };
    assert.equal((await ask("claims", rep, year)).data.total, 3, "a year back is allowed, and finds the old draft");
    const tooLong = { scope: "mine", from: "2025-01-01T00:00:00Z", to: "2026-12-31T00:00:00Z" };
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

describe("AskMira: claims filed and decided from Ask Mira", { skip: SKIP }, () => {
  let db;
  let api;
  const T = crypto.randomUUID();
  const actor = (email, role = "employee") => ({ id: crypto.randomUUID(), email, role });
  const hr = actor("hr@claims.co", "admin");
  const mgr = actor("mgr@claims.co");
  const rep = actor("rep@claims.co");
  const loner = actor("loner@claims.co");
  const today = new Date().toISOString().split("T")[0];

  async function act(kind, who, params = {}) {
    const payload = { tenant_id: T, actor: who, kind, params };
    const body = JSON.stringify(payload);
    const bh = crypto.createHash("sha256").update(body).digest("hex");
    const t = await token("act", T, { bh });
    return api.call("POST", "/integrations/askmira/act", { headers: { Authorization: `Bearer ${t}` }, body });
  }

  async function provision(pathname, payload) {
    const body = JSON.stringify(payload);
    const bh = crypto.createHash("sha256").update(body).digest("hex");
    const t = await token("provision", payload.tenant_id, { bh });
    return api.call("POST", `/integrations/askmira${pathname}`, { headers: { Authorization: `Bearer ${t}` }, body });
  }

  before(async () => {
    db = await resetDatabase();
    api = await startApi({ ASKMIRA_SHARED_SECRET: SECRET });
    assert.equal((await provision("/organizations", { tenant_id: T, name: "Claims Co", slug: "claimsco", domain: null })).status, 200);
    await seedPeople(db, [
      ["hr@claims.co", "HR", "admin", "claimsco"],
      ["mgr@claims.co", "Mgr", "employee", "claimsco", "hr@claims.co"],
      ["rep@claims.co", "Rep", "employee", "claimsco", "mgr@claims.co", "hr@claims.co"],
      ["loner@claims.co", "Loner", "employee", "claimsco"],
    ]);
    await db.query(`UPDATE employees SET grade = 'G1' WHERE email = 'rep@claims.co'`);
    await db.query(
      `INSERT INTO expense_categories (slug, name, normalized, requires_bill) VALUES
         ('claimsco', 'Travel', 'TRAVEL', false), ('claimsco', 'Meals', 'MEALS', true)`,
    );
    await db.query(
      `INSERT INTO tenant_policy_caps (slug, normalized, grade, cap_amount, is_actuals) VALUES
         ('claimsco', 'TRAVEL', 'G1', 2000, false)`,
    );
  });

  after(async () => {
    await api?.stop();
    await db?.end();
  });

  // Each call is its own bill: a bill already claimed is refused.
  const cab = (amount = "850.50", category = "travel", invoice = `UB-${crypto.randomUUID().slice(0, 8)}`) => ({
    key: `msg-${crypto.randomUUID()}`,
    title: "Cab to the client",
    lines: [{ category, amount, date: today, vendor: "Uber", invoice_number: invoice, description: "Airport to office" }],
  });

  async function ask(kind, who, params = {}) {
    const payload = { tenant_id: T, actor: who, kind, params };
    const body = JSON.stringify(payload);
    const bh = crypto.createHash("sha256").update(body).digest("hex");
    const t = await token("query", T, { bh });
    return api.call("POST", "/integrations/askmira/query", { headers: { Authorization: `Bearer ${t}` }, body });
  }

  test("a claim from a receipt goes to the manager, once, with its lines as the app writes them", async () => {
    const params = cab();
    const filed = await act("claim.create", rep, params);
    assert.equal(filed.status, 200, JSON.stringify(filed.data));
    assert.equal(filed.data.claim.status, "Pending");
    assert.equal(filed.data.claim.approver, "mgr@claims.co");
    assert.equal(filed.data.claim.amount, "850.50");
    const { rows } = await db.query(`SELECT * FROM expenses WHERE unique_key = $1`, [`askmira:${params.key}`]);
    assert.equal(rows.length, 1);
    const [line] = rows[0].data.ExpenseData;
    assert.equal(line.Category, "Travel");
    assert.equal(line.InvoiceAmount, 850.5);
    assert.equal(line.VendorName, "Uber");
    assert.equal(rows[0].submitter_email, "rep@claims.co");
    // Asking again returns the same claim, never a second.
    const again = await act("claim.create", rep, params);
    assert.equal(again.data.existing, true);
    const count = await db.query(`SELECT COUNT(*)::int AS n FROM expenses WHERE unique_key = $1`, [`askmira:${params.key}`]);
    assert.equal(count.rows[0].n, 1);
  });

  test("a category that needs a bill stays a draft until the bill is attached", async () => {
    const filed = await act("claim.create", rep, { ...cab("400", "Meals"), title: "Team lunch" });
    assert.equal(filed.status, 200, JSON.stringify(filed.data));
    assert.equal(filed.data.claim.status, "Draft");
    assert.deepEqual(filed.data.needs_bill, ["Meals"]);
  });

  test("the grade's cap, the categories, the amount and the date are checked", async () => {
    const over = await act("claim.create", rep, cab("2500"));
    assert.equal(over.status, 422);
    assert.match(over.data.error, /Travel is capped at ₹2,000 for grade G1; this bill is ₹2,500/);
    const unknown = await act("claim.create", rep, cab("100", "Yacht"));
    assert.equal(unknown.status, 422);
    assert.match(unknown.data.error, /"Yacht" is not a category here. These are: Meals, Travel/);
    for (const amount of ["abc", "-5", "0", "12.345", "1e5", ""]) {
      assert.equal((await act("claim.create", rep, cab(amount))).status, 422, `amount ${amount}`);
    }
    const future = cab();
    future.lines[0].date = "2999-01-01";
    assert.equal((await act("claim.create", rep, future)).status, 422);
    const noKey = { ...cab(), key: "" };
    assert.equal((await act("claim.create", rep, noKey)).status, 422);
    const nobody = await act("claim.create", loner, cab());
    assert.equal(nobody.status, 422);
    assert.match(nobody.data.error, /No approver is set for you/);
    const stranger = await act("claim.create", actor("stranger@else.com"), cab());
    assert.equal(stranger.status, 403);
  });

  test("the approver decides it through the same two levels; nobody else can", async () => {
    const filed = await act("claim.create", rep, cab("300"));
    const reference = filed.data.claim.reference;
    assert.equal((await act("claim.decide", rep, { reference, decision: "approve" })).status, 403, "own claim");
    assert.equal((await act("claim.decide", loner, { reference, decision: "approve" })).status, 403);
    assert.equal((await act("claim.decide", mgr, { reference, decision: "reject" })).status, 422, "a rejection needs a reason");

    const first = await act("claim.decide", mgr, { reference, decision: "approve", comment: "Fine" });
    assert.equal(first.status, 200, JSON.stringify(first.data));
    // Approved by the manager, it waits on finance now.
    assert.equal(first.data.claim.status, "Pending");
    assert.equal(first.data.claim.next_approver, "hr@claims.co");
    assert.equal((await act("claim.decide", mgr, { reference, decision: "approve" })).status, 403, "no longer theirs");
    // An ExpGenie admin who is not its approver can't finalise it from Ask Mira either.
    assert.equal((await act("claim.decide", actor("other-admin@claims.co", "admin"), { reference, decision: "approve" })).status, 403);

    const final = await act("claim.decide", hr, { reference, decision: "approve" });
    assert.equal(final.data.claim.status, "Approved");
    assert.equal((await act("claim.decide", hr, { reference, decision: "approve" })).status, 409, "decided already");
    const { rows } = await db.query(`SELECT data FROM expenses WHERE unique_key = $1`, [reference]);
    assert.ok(rows[0].data.ApprovalHistory.some((h) => /Fine \(from Ask Mira\)/.test(h.comments)));
  });

  test("one bill split into lines is still over the cap; separate bills each count alone", async () => {
    const split = cab("2000", "travel", "UB-SPLIT");
    split.lines.push({ ...split.lines[0], amount: "500", description: "balance" });
    const refused = await act("claim.create", rep, split);
    assert.equal(refused.status, 422, JSON.stringify(refused.data));
    assert.match(refused.data.error, /Travel is capped at ₹2,000 for grade G1; this bill is ₹2,500/);

    const two = cab("1500", "travel", "UB-A1");
    two.lines.push({ ...two.lines[0], amount: "1200", invoice_number: "UB-A2" });
    const filed = await act("claim.create", rep, two);
    assert.equal(filed.status, 200, JSON.stringify(filed.data));
    assert.equal(filed.data.claim.amount, "2700.00");
  });

  test("a bill already claimed is refused, and named in the bills query", async () => {
    const first = cab("640", "travel", "UB-DUP");
    assert.equal((await act("claim.create", rep, first)).status, 200);
    const again = await act("claim.create", rep, { ...cab("640", "travel", "UB-DUP"), title: "Same cab" });
    assert.equal(again.status, 409);
    assert.match(again.data.error, /already claimed in “Cab to the client” \(Pending\)/);
    // The same vendor, date and amount with no invoice number is the same bill too.
    const bare = cab("777", "travel", "");
    assert.equal((await act("claim.create", rep, bare)).status, 200);
    assert.equal((await act("claim.create", rep, cab("777", "travel", ""))).status, 409);

    const asked = await ask("bills", rep, { lines: first.lines });
    assert.equal(asked.status, 200, JSON.stringify(asked.data));
    assert.equal(asked.data.duplicates.length, 1);
    assert.equal(asked.data.duplicates[0].line, 1);
    // Someone else's claim of the same invoice is not theirs to know of.
    const mine = await ask("bills", loner, { lines: first.lines });
    assert.deepEqual(mine.data.duplicates, []);
  });

  test("a rejection keeps its reason; a claim is decided by its own id", async () => {
    const filed = await act("claim.create", rep, cab("410"));
    const { reference } = filed.data.claim;
    const waiting = await ask("claims", mgr, { scope: "approvals", status: "pending", query: "Rep cab" });
    assert.equal(waiting.status, 200, JSON.stringify(waiting.data));
    const listed = waiting.data.claims.find((c) => c.reference === reference);
    assert.ok(listed && listed.id, "each claim names its own id; 'Rep cab' matches by words");
    const rejected = await act("claim.decide", mgr, {
      id: listed.id, reference, decision: "reject", comment: "Client visit was cancelled",
    });
    assert.equal(rejected.status, 200, JSON.stringify(rejected.data));
    const { rows } = await db.query(`SELECT data FROM expenses WHERE id = $1`, [listed.id]);
    assert.equal(rows[0].data.RejectionInfo.Reason, "Client visit was cancelled");
    assert.equal(rows[0].data.ApprovalHistory.at(-1).reason, "Client visit was cancelled");
  });

  test("two references alike are refused rather than guessed", async () => {
    const a = await act("claim.create", rep, cab("120"));
    const b = await act("claim.create", rep, cab("130"));
    await db.query(`UPDATE expenses SET unique_key = 'R-77' WHERE unique_key IN ($1, $2)`, [
      a.data.claim.reference, b.data.claim.reference,
    ]);
    const decided = await act("claim.decide", mgr, { reference: "R-77", decision: "approve" });
    assert.equal(decided.status, 409);
  });

  test("a suspended workspace neither files, decides nor reads through AskMira", async () => {
    await db.query(`UPDATE tenant_settings SET status = 'suspended' WHERE slug = 'claimsco'`);
    try {
      assert.equal((await act("claim.create", rep, cab("90"))).status, 403);
      assert.equal((await ask("claims", rep, { scope: "mine" })).status, 403);
    } finally {
      await db.query(`UPDATE tenant_settings SET status = 'active' WHERE slug = 'claimsco'`);
    }
  });
});

describe("AskMira: the categories a person may claim under", { skip: SKIP }, () => {
  let db;
  let api;
  const T = crypto.randomUUID();
  const rep = { id: crypto.randomUUID(), email: "rep@cats.co", role: "employee" };

  async function ask(kind, who, params = {}) {
    const payload = { tenant_id: T, actor: who, kind, params };
    const body = JSON.stringify(payload);
    const bh = crypto.createHash("sha256").update(body).digest("hex");
    const t = await token("query", T, { bh });
    return api.call("POST", "/integrations/askmira/query", { headers: { Authorization: `Bearer ${t}` }, body });
  }

  before(async () => {
    db = await resetDatabase();
    api = await startApi({ ASKMIRA_SHARED_SECRET: SECRET });
    const body = JSON.stringify({ tenant_id: T, name: "Cats", slug: "cats", domain: null });
    const bh = crypto.createHash("sha256").update(body).digest("hex");
    const t = await token("provision", T, { bh });
    await api.call("POST", "/integrations/askmira/organizations", { headers: { Authorization: `Bearer ${t}` }, body });
    await seedPeople(db, [["rep@cats.co", "Rep", "employee", "cats"]]);
    await db.query(`UPDATE employees SET grade = 'G2' WHERE email = 'rep@cats.co'`);
    await db.query(`INSERT INTO expense_categories (slug, name, normalized, requires_bill, enabled) VALUES
      ('cats', 'Travel', 'TRAVEL', false, true), ('cats', 'Meals', 'MEALS', true, true),
      ('cats', 'Retired', 'OLD', true, false), ('other', 'Secret', 'SEC', true, true)`);
    await db.query(`INSERT INTO tenant_policy_caps (slug, normalized, grade, cap_amount, is_actuals) VALUES
      ('cats', 'TRAVEL', 'G2', 1500, false), ('cats', 'MEALS', 'G2', 900, true), ('cats', 'TRAVEL', 'G9', 99, false)`);
  });

  after(async () => {
    await api?.stop();
    await db?.end();
  });

  test("this workspace's enabled categories, with the person's own grade cap", async () => {
    const answer = await ask("categories", rep);
    assert.equal(answer.status, 200, JSON.stringify(answer.data));
    assert.equal(answer.data.grade, "G2");
    assert.deepEqual(answer.data.categories, [
      { name: "Meals", requires_bill: true, cap: null },
      { name: "Travel", requires_bill: false, cap: "1500" },
    ]);
  });
});
