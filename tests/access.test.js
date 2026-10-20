// Who may see and do what, end to end against a real database.
//
// Two tenants (acme, beta), a super-admin and a suspended tenant (gamma). Each
// test is one area; they share one API process and run in order.

const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { SignJWT } = require("jose");
const { SKIP, PASSWORD, resetDatabase, seedPeople, startApi, signIn } = require("./support/server");

const RECEIPT = "s3://expense_receipt/beta-user/r1.jpg";

describe("access control", { skip: SKIP }, () => {
  let db;
  let api;
  const T = {};

  before(async () => {
    db = await resetDatabase();
    await seedPeople(db, [
      ["sa@platform.com", "Super", "super_admin", null],
      ["admin@acme.com", "Acme Admin", "admin", "acme"],
      ["emp@acme.com", "Acme Emp", "employee", "acme", "mgr@acme.com", "fin@acme.com"],
      ["mgr@acme.com", "Acme Mgr", "employee", "acme"],
      ["fin@acme.com", "Acme Fin", "employee", "acme"],
      ["nomgr@acme.com", "No Manager", "employee", "acme"],
      ["admin@beta.com", "Beta Admin", "admin", "beta"],
      ["emp@beta.com", "Beta Emp", "employee", "beta", "admin@beta.com"],
      ["emp@gamma.com", "Gamma Emp", "employee", "gamma"],
    ]);
    await db.query(`INSERT INTO tenant_settings (slug, name, plan, status) VALUES
      ('acme','Acme','growth','active'), ('beta','Beta','growth','active'),
      ('gamma','Gamma','growth','suspended')`);
    await db.query(
      `INSERT INTO expenses (id, user_id, unique_key, approver_email, submitter_email, submitter_name,
                             approval_status, data, created_at)
       VALUES ('X1','emp@beta.com','X1','admin@beta.com','emp@beta.com','Beta Emp','Pending',$1,
               now() - interval '1 day'),
              ('X2','emp@acme.com','X2','mgr@acme.com','emp@acme.com','Acme Emp','Pending',$2,
               now() - interval '1 day')`,
      [
        { ExpenseData: [{ InvoiceAmount: 100, File: [{ blob_url: RECEIPT, filename: "r1.jpg" }] }] },
        { ExpenseData: [{ InvoiceAmount: 50 }] },
      ],
    );
    api = await startApi();
    for (const email of ["sa@platform.com", "admin@acme.com", "emp@acme.com", "mgr@acme.com",
      "fin@acme.com", "nomgr@acme.com", "admin@beta.com", "emp@beta.com"]) {
      T[email] = await signIn(api, email);
    }
  });

  after(async () => {
    await api?.stop();
    await db?.end();
  });

  const get = (url, token) => api.call("GET", url, { token });

  test("sign-in", async () => {
    const wrong = await api.call("POST", "/auth/login", { body: { email: "emp@acme.com", password: "nope" } });
    const ghost = await api.call("POST", "/auth/login", { body: { email: "ghost@acme.com", password: "nope" } });
    assert.equal(wrong.status, 401);
    assert.equal(wrong.data.error, "Invalid email or password");
    assert.equal(ghost.status, 401);
    assert.equal(ghost.data.error, wrong.data.error, "an unknown email must look like a wrong password");

    const gamma = await api.call("POST", "/auth/login", { body: { email: "emp@gamma.com", password: PASSWORD } });
    assert.equal(gamma.status, 403, "a suspended tenant can't sign in");

    const me = await get("/auth/me", T["emp@acme.com"]);
    assert.equal(me.data.user.email, "emp@acme.com");
    assert.equal((await get("/auth/me?email=emp@beta.com", T["emp@acme.com"])).status, 403);
  });

  test("forged and tampered tokens", async () => {
    const forged = await new SignJWT({ role: "super_admin" })
      .setProtectedHeader({ alg: "HS256" }).setSubject("sa@platform.com").setIssuer("expgenie")
      .setAudience("expgenie-api").setIssuedAt().setExpirationTime("1h")
      .sign(new TextEncoder().encode("some-other-secret-xxxxxxxxxxxxxxxxxxxx"));
    assert.equal((await get("/tenants", forged)).status, 401);
    const t = T["emp@acme.com"];
    const tampered = t.slice(0, -3) + (t.slice(-3) === "AAA" ? "BBB" : "AAA");
    assert.equal((await get("/auth/me", tampered)).status, 401);
    // The dashboard's old hand-made session, which anyone could write.
    const oldStyle = Buffer.from(JSON.stringify({ sub: "sa@platform.com", role: "super_admin", exp: Date.now() + 1e7 })).toString("base64url");
    assert.equal((await get("/tenants", oldStyle)).status, 401);
  });

  test("reading expenses", async () => {
    const cases = [
      ["/master-expense?email=emp@acme.com", "emp@acme.com", 200],
      ["/master-expense?email=emp@beta.com", "emp@acme.com", 403],
      ["/master-expense?email=emp@acme.com", "admin@acme.com", 200],
      ["/master-expense?email=emp@beta.com", "admin@acme.com", 403],
      ["/master-expense/approver?email=mgr@acme.com", "emp@acme.com", 403],
      ["/master-expense/counts?email=emp@beta.com", "emp@acme.com", 403],
      ["/master-expense/tenant?slug=acme", "emp@acme.com", 403],
      ["/master-expense/tenant?slug=acme", "admin@acme.com", 200],
      ["/master-expense/tenant?slug=beta", "admin@acme.com", 403],
      ["/master-expense/all", "admin@acme.com", 403],
      ["/master-expense/all", "sa@platform.com", 200],
    ];
    for (const [url, who, status] of cases) {
      assert.equal((await get(url, T[who])).status, status, `${who} GET ${url}`);
    }
  });

  test("submitting expenses", async () => {
    const submit = (who, body) => api.call("POST", "/master-expense", { token: T[who], body });
    const base = { ExpenseTitle: "x", ApprovalStatus: "Pending", ExpenseData: [] };

    const asSomeoneElse = await submit("emp@acme.com", { ...base, ApproverEmail: "mgr@acme.com", SubmitterEmail: "emp@beta.com" });
    assert.equal(asSomeoneElse.status, 403);

    const sneaky = await submit("emp@acme.com", {
      ...base, ApproverEmail: "emp@acme.com", SubmitterEmail: "EMP@acme.com", ApprovalStatus: "Approved",
      ExpenseData: [{ InvoiceAmount: 10 }],
    });
    assert.equal(sneaky.status, 200);
    assert.equal(sneaky.data.ApprovalStatus, "Pending", "an expense is never born approved");
    assert.equal(sneaky.data.ApproverEmail, "mgr@acme.com", "the approver comes from the record");
    assert.equal(sneaky.data.SubmitterEmail, "emp@acme.com");
    T.sneakyId = sneaky.data.id;

    const draft = await submit("emp@acme.com", { ...base, ApproverEmail: "mgr@acme.com", SubmitterEmail: "emp@acme.com", ApprovalStatus: "Draft" });
    assert.equal(draft.data.ApprovalStatus, "Draft");
    T.draftId = draft.data.id;

    const self = await submit("nomgr@acme.com", { ...base, ApproverEmail: "nomgr@acme.com", SubmitterEmail: "nomgr@acme.com" });
    assert.equal(self.status, 400, "no manager on record, and approving yourself is refused");
    const foreign = await submit("nomgr@acme.com", { ...base, ApproverEmail: "admin@beta.com", SubmitterEmail: "nomgr@acme.com" });
    assert.equal(foreign.status, 400, "an approver from another tenant is refused");
    const ok = await submit("nomgr@acme.com", { ...base, ApproverEmail: "admin@acme.com", SubmitterEmail: "nomgr@acme.com" });
    assert.equal(ok.data.ApproverEmail, "admin@acme.com");
  });

  test("approving and rejecting", async () => {
    const put = (who, id, body) => api.call("PUT", `/master-expense/${id}`, { token: T[who], body });
    assert.equal((await put("emp@acme.com", "X2", { ApprovalStatus: "Approved" })).status, 403);
    assert.equal((await put("admin@beta.com", "X2", { ApprovalStatus: "Rejected" })).status, 403);
    assert.equal((await put("mgr@acme.com", "X2", { ApprovalStatus: "Paid" })).status, 400);

    const approved = await put("mgr@acme.com", "X2", { ApprovalStatus: "Approved", UpdatedBy: "ceo@acme.com" });
    assert.equal(approved.data.ApprovalStatus, "Pending");
    assert.equal(approved.data.ApproverEmail, "fin@acme.com", "the manager's approval forwards to finance");
    assert.equal(approved.data.ApprovalHistory.at(-1).by, "mgr@acme.com", "history records the caller, not UpdatedBy");
    assert.equal((await put("mgr@acme.com", "X2", { ApprovalStatus: "Approved" })).status, 403);

    const final = await api.call("PUT", "/master-expense/by-id/X2", { token: T["fin@acme.com"], body: { ApprovalStatus: "Approved" } });
    assert.equal(final.data.ApprovalStatus, "Approved");
    assert.equal((await put("admin@acme.com", "X2", { ApprovalStatus: "Rejected" })).status, 409);

    assert.equal((await put("emp@acme.com", T.draftId, { ApprovalStatus: "Pending" })).status, 200);
    assert.equal((await put("admin@acme.com", T.sneakyId, { ApprovalStatus: "Rejected", RejectionReason: "x" })).status, 200);
    assert.equal((await put("emp@acme.com", T.sneakyId, { ApprovalStatus: "Approved" })).status, 403);
  });

  test("notification emails go only to people on the expense", async () => {
    const notify = (who, body) => api.call("POST", "/master-expense/notify", { token: T[who], body });
    assert.equal((await notify("emp@acme.com", { eventType: "expense.submitted", expense: { id: "X1" } })).status, 403);
    assert.equal((await notify("emp@beta.com", { eventType: "expense.submitted", expense: { id: "X1" }, recipient: "victim@evil.com" })).status, 400);
    const ok = await notify("emp@beta.com", { eventType: "expense.submitted", expense: { id: "X1", SubmitterEmail: "x@evil.com" } });
    assert.equal(ok.data.recipient, "admin@beta.com");
  });

  test("receipts", async () => {
    const sign = (who, p = RECEIPT) => get(`/storage/sign?path=${encodeURIComponent(p)}`, T[who]);
    assert.equal((await sign("emp@acme.com")).status, 403);
    // Past the access check; signing then fails against the stand-in storage.
    assert.ok(![401, 403].includes((await sign("emp@beta.com")).status));
    assert.ok(![401, 403].includes((await sign("admin@beta.com")).status));

    // Pasting someone else's receipt path into your own expense doesn't unlock it.
    await api.call("POST", "/master-expense", {
      token: T["emp@acme.com"],
      body: {
        ExpenseTitle: "steal", ApproverEmail: "mgr@acme.com", SubmitterEmail: "emp@acme.com", ApprovalStatus: "Pending",
        ExpenseData: [{ InvoiceAmount: 1, File: [{ blob_url: RECEIPT }] }],
      },
    });
    assert.equal((await sign("emp@acme.com")).status, 403);
    assert.equal((await sign("sa@platform.com", "s3://other-bucket/x.jpg")).status, 403);
  });

  test("people and tenants", async () => {
    const acme = await get("/users", T["admin@acme.com"]);
    assert.equal(acme.status, 200);
    assert.ok(acme.data.every((u) => u.tenant === "acme"));
    assert.equal(acme.data.length, 5);
    assert.equal((await get("/users", T["sa@platform.com"])).data.length, 9);

    const cases = [
      ["GET", "/users?tenant=beta", "admin@acme.com", 403],
      ["GET", "/users", "emp@acme.com", 403],
      ["GET", "/users/emp@beta.com", "admin@acme.com", 403],
      ["PUT", "/users/emp@beta.com", "admin@acme.com", 403, { department: "x" }],
      ["PUT", "/users/emp@acme.com", "admin@acme.com", 200, { department: "Ops" }],
      ["PUT", "/users/mgr@acme.com", "emp@acme.com", 403, { role: "admin" }],
      ["DELETE", "/users/emp@beta.com", "admin@acme.com", 403],
      ["POST", "/users", "admin@acme.com", 403, { tenantSlug: "beta", email: "n@beta.com", displayName: "N", role: "admin" }],
      ["POST", "/users/bulk", "admin@acme.com", 403, { tenantSlug: "beta", users: [{ email: "n@beta.com", name: "N" }] }],
      ["PATCH", "/users/mgr@acme.com/profile", "emp@acme.com", 403, { avatarUrl: null }],
      ["PATCH", "/users/emp@acme.com/profile", "emp@acme.com", 200, { integrationProvider: "email" }],
      ["GET", "/tenants", "admin@acme.com", 403],
      ["GET", "/tenants", "sa@platform.com", 200],
      ["GET", "/tenants/acme", "emp@acme.com", 200],
      ["GET", "/tenants/beta", "emp@acme.com", 403],
      ["POST", "/tenants", "admin@acme.com", 403, { name: "Evil", adminName: "E", adminEmail: "e@evil.com", plan: "growth" }],
      ["PATCH", "/tenants/beta", "admin@acme.com", 403, { status: "suspended" }],
      ["GET", "/admin/overview", "admin@acme.com", 403],
      ["GET", "/admin/overview", "sa@platform.com", 200],
      ["GET", "/admin/tenant-overview?tenant=beta", "admin@acme.com", 403],
      ["GET", "/admin/tenant-overview?tenant=acme", "admin@acme.com", 200],
    ];
    for (const [method, url, who, status, body] of cases) {
      assert.equal((await api.call(method, url, { token: T[who], body })).status, status, `${who} ${method} ${url}`);
    }
  });

  test("notifications are personal", async () => {
    const { rows: [n] } = await db.query(
      `INSERT INTO notifications (recipient_email, type, title, body) VALUES ('emp@beta.com','x','t','b') RETURNING id`,
    );
    assert.equal((await api.call("PUT", `/notifications/${n.id}/read`, { token: T["emp@acme.com"] })).status, 404);
    const peek = await get("/notifications?email=emp@beta.com", T["emp@acme.com"]);
    assert.ok(peek.data.every((x) => x.id !== n.id), "the email parameter is ignored");
    assert.equal((await api.call("PUT", `/notifications/${n.id}/read`, { token: T["emp@beta.com"] })).status, 200);
  });

  test("tenant configuration", async () => {
    const call = (method, url, who, body) => api.call(method, url, { token: T[who], body });
    assert.equal((await call("POST", "/categories", "admin@acme.com", { slug: "beta", name: "Evil" })).status, 403);
    const cat = await call("POST", "/categories", "admin@beta.com", { slug: "beta", name: "Travel" });
    assert.equal(cat.status, 201);
    assert.equal((await call("PUT", `/categories/${cat.data.id}`, "admin@acme.com", { name: "x" })).status, 403);
    assert.equal((await call("DELETE", `/categories/${cat.data.id}`, "admin@acme.com")).status, 403);
    assert.equal((await call("GET", "/categories?slug=beta", "emp@beta.com")).status, 200);
    assert.equal((await call("GET", "/categories?slug=beta", "emp@acme.com")).status, 403);
    assert.equal((await call("POST", "/categories", "emp@beta.com", { slug: "beta", name: "x" })).status, 403);

    const rule = await call("POST", "/rules", "admin@beta.com", { slug: "beta", name: "R" });
    assert.equal((await call("PUT", `/rules/${rule.data.id}`, "admin@acme.com", { name: "x" })).status, 403);
    assert.equal((await call("GET", "/rules?slug=beta", "admin@acme.com")).status, 403);

    assert.equal((await call("GET", "/master-config/beta", "admin@acme.com")).status, 403);
    const cap = await call("POST", "/master-config/beta/policy-caps", "admin@beta.com", { normalized: "Travel", grade: "G1", capAmount: 100 });
    assert.equal(cap.status, 201);
    assert.equal((await call("PUT", `/master-config/acme/policy-caps/${cap.data.id}`, "admin@acme.com", { capAmount: 1 })).status, 404);
    assert.equal((await call("DELETE", `/master-config/acme/policy-caps/${cap.data.id}`, "admin@acme.com")).status, 404);

    const cfg = await call("PUT", "/tenant-config/acme", "admin@acme.com", { config: { currency: "USD", manualPaymentEnabled: true } });
    assert.equal(cfg.data.config.currency, "USD");
    assert.equal(cfg.data.config.manualPaymentEnabled, false, "only a super-admin turns on manual payment");
    const cfg2 = await call("PUT", "/tenant-config/acme", "sa@platform.com", { config: { manualPaymentEnabled: true } });
    assert.equal(cfg2.data.config.manualPaymentEnabled, true);
    assert.equal((await call("PUT", "/tenant-config/beta", "admin@acme.com", { config: { currency: "USD" } })).status, 403);
    assert.equal((await call("GET", "/tenant-config/acme", "emp@acme.com")).status, 200);

    await call("PUT", "/integrations/acme", "admin@acme.com", { sap: { enabled: true, username: "sapuser", password: "s3cret", companyCode: "1000" } });
    const asAdmin = await call("GET", "/integrations/acme", "admin@acme.com");
    assert.equal(asAdmin.data.sap.username, "sapuser");
    assert.equal(asAdmin.data.sap.passwordSet, true);
    const asEmp = await call("GET", "/integrations/acme", "emp@acme.com");
    assert.equal(asEmp.data.sap.companyCode, "1000");
    assert.ok(!("username" in asEmp.data.sap) && !("passwordSet" in asEmp.data.sap), "employees see coding fields only");
    assert.equal((await call("GET", "/integrations/beta", "emp@acme.com")).status, 403);
    assert.equal((await call("PUT", "/integrations/acme", "emp@acme.com", { sap: { enabled: false } })).status, 403);
    const meta = await call("POST", "/integrations/acme/sap/test", "admin@acme.com", { baseUrl: "http://169.254.169.254/latest/meta-data" });
    assert.equal(meta.data.ok, false);
    assert.match(meta.data.message, /can't be tested/);
    const loop = await call("POST", "/integrations/acme/sap/test", "admin@acme.com", { baseUrl: "http://localhost:1/" });
    assert.equal(loop.data.ok, false);
  });

  test("manual payment", async () => {
    const stranger = await api.call("POST", "/master-expense/X2/payment", { token: T["emp@beta.com"], body: { UpdatedBy: "fin@acme.com" } });
    assert.ok([403, 409].includes(stranger.status));
    const paid = await api.call("POST", "/master-expense/X2/payment", { token: T["fin@acme.com"], body: { UpdatedBy: "someone@else.com" } });
    assert.equal(paid.status, 200);
    assert.equal(paid.data.PaymentInfo.PaidBy, "fin@acme.com", "recorded as the caller");
  });

  test("microsoft sign-in is refused when not configured", async () => {
    assert.equal((await api.call("POST", "/auth/microsoft", { body: { idToken: "x" } })).status, 503);
  });

  test("a password reset ends earlier sessions", async () => {
    await new Promise((r) => setTimeout(r, 1100)); // sessions are compared to the second
    await db.query(`INSERT INTO password_resets (token, email, expires_at) VALUES ('tok-1','emp@beta.com', now() + interval '1 hour')`);
    assert.equal((await api.call("POST", "/auth/reset-password", { body: { token: "tok-1", password: "NewPassw0rd!" } })).status, 200);
    assert.equal((await get("/auth/me", T["emp@beta.com"])).status, 401);
    const fresh = await signIn(api, "emp@beta.com", "NewPassw0rd!");
    assert.equal((await get("/auth/me", fresh)).status, 200);
  });

  test("suspension and deletion take effect at once", async () => {
    await db.query(`UPDATE tenant_settings SET status = 'suspended' WHERE slug = 'beta'`);
    assert.equal((await get("/auth/me", T["admin@beta.com"])).status, 403);
    await db.query(`UPDATE tenant_settings SET status = 'active' WHERE slug = 'beta'`);
    await db.query(`DELETE FROM employees WHERE email = 'nomgr@acme.com'`);
    assert.equal((await get("/auth/me", T["nomgr@acme.com"])).status, 401);
  });

  test("password guessing is throttled", async () => {
    let last;
    for (let i = 0; i < 11; i++) {
      last = await api.call("POST", "/auth/login", { body: { email: "fin@acme.com", password: "bad" } });
    }
    assert.equal(last.status, 429);
  });

  test("browsers may call only from the dashboard's origin", async () => {
    const preflight = (origin) =>
      fetch(`${api.base}/users`, { method: "OPTIONS", headers: { Origin: origin, "Access-Control-Request-Method": "GET" } });
    assert.equal((await preflight("https://evil.example")).headers.get("access-control-allow-origin"), null);
    assert.equal((await preflight("http://localhost:3000")).headers.get("access-control-allow-origin"), "http://localhost:3000");
  });
});

describe("report mode (AUTH_ENFORCEMENT=report, for old mobile builds)", { skip: SKIP }, () => {
  let db;
  let api;

  before(async () => {
    db = await resetDatabase();
    await seedPeople(db, [
      ["emp@acme.com", "Acme Emp", "employee", "acme"],
      ["emp@beta.com", "Beta Emp", "employee", "beta"],
    ]);
    api = await startApi({ AUTH_ENFORCEMENT: "report" });
  });

  after(async () => {
    await api?.stop();
    await db?.end();
  });

  test("a request without a token is still served, and logged", async () => {
    assert.equal((await api.call("GET", "/master-expense?email=emp@beta.com")).status, 200);
    assert.match(api.log(), /report mode: GET \/master-expense called without a token/);
  });

  test("a request with a token is still checked", async () => {
    const token = await signIn(api, "emp@acme.com");
    assert.equal((await api.call("GET", "/master-expense?email=emp@beta.com", { token })).status, 403);
    assert.equal((await api.call("GET", "/master-expense?email=emp@beta.com", { token: "garbage" })).status, 401);
  });

  test("without a token, only the receipts bucket can be signed", async () => {
    const avatar = encodeURIComponent("https://x.supabase.co/storage/v1/object/public/avatars/a.png");
    assert.equal((await api.call("GET", `/storage/sign?path=${avatar}`)).status, 403);
  });
});
