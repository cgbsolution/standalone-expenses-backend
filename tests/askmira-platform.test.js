// AskMira's platform creating or attaching a workspace here (routes/askmira_platform.js).
//
// Tokens are minted the way AskMira mints them: HS256 with the platform key,
// aud "askmira:expense", iss "askmira", sub and use "platform", `bh` = SHA-256
// of the exact body. The secret it answers with is then used as AskMira uses it.

const crypto = require("crypto");
const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { SignJWT } = require("jose");
const { SKIP, resetDatabase, seedPeople, startApi } = require("./support/server");

const PLATFORM = "askmira-platform-key-0123456789abcdef0123";

function sign(secret, sub, use, body) {
  const bh = crypto.createHash("sha256").update(body).digest("hex");
  return new SignJWT({ use, bh })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer("askmira").setAudience("askmira:expense").setSubject(sub)
    .setIssuedAt().setExpirationTime("60s").setJti(crypto.randomUUID())
    .sign(new TextEncoder().encode(secret));
}

describe("AskMira platform switched off", { skip: SKIP }, () => {
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

  test("without ASKMIRA_PLATFORM_SECRET the endpoints don't exist", async () => {
    const body = JSON.stringify({ check: true });
    const r = await api.call("POST", "/integrations/askmira/platform/ping", {
      body,
      token: await sign(PLATFORM, "platform", "platform", body),
    });
    assert.equal(r.status, 404);
  });
});

describe("AskMira platform", { skip: SKIP }, () => {
  let db;
  let api;
  const call = async (action, payload, { secret = PLATFORM, sub = "platform", use = "platform", path } = {}) => {
    const body = JSON.stringify(payload);
    return api.call("POST", path || `/integrations/askmira/platform/${action}`, {
      body,
      token: await sign(secret, sub, use, body),
    });
  };
  const company = (tenantId, extra = {}) => ({
    tenant_id: tenantId,
    tenant_name: "Newco",
    askmira_origin: "https://askmira.example",
    company: { name: "Newco Pvt Ltd", slug: "newco", domain: "newco.com" },
    admin: { email: "Asha@Newco.com", name: "Asha" },
    organization_ref: null,
    create_new: false,
    ...extra,
  });

  before(async () => {
    db = await resetDatabase();
    await seedPeople(db, [
      ["owner@beta.com", "Owner", "admin", "beta"],
      ["ops@beta.com", "Ops", "employee", "beta"],
    ]);
    await db.query(`INSERT INTO tenant_settings (slug, name, plan, status) VALUES ('beta', 'Beta Ltd', 'growth', 'active')`);
    api = await startApi({ ASKMIRA_PLATFORM_SECRET: PLATFORM });
  });
  after(async () => {
    await api?.stop();
    await db?.end();
  });

  test("a wrong key or another use is refused", async () => {
    assert.equal((await call("ping", { check: true })).status, 200);
    assert.equal((await call("ping", { check: true }, { secret: "x".repeat(40) })).status, 401);
    assert.equal((await call("ping", { check: true }, { use: "provision" })).status, 401);
  });

  test("provision creates the workspace and its admin, and the secret works", async () => {
    const t1 = crypto.randomUUID();
    const r = await call("provision", company(t1));
    assert.equal(r.status, 200, JSON.stringify(r.data));
    assert.equal(r.data.created, true);
    assert.equal(r.data.admin_created, true);
    assert.equal(r.data.organization, "Newco Pvt Ltd");
    const slug = r.data.external_ref;
    const { rows } = await db.query(`SELECT role, tenant FROM employees WHERE email = 'asha@newco.com'`);
    assert.deepEqual(rows[0], { role: "admin", tenant: slug });

    const sync = await call(
      null,
      { tenant_id: t1, complete: true, users: [{ id: "u1", email: "asha@newco.com", name: "Asha", role: "admin" }] },
      { secret: r.data.secret, sub: t1, use: "provision", path: "/integrations/askmira/users/sync" },
    );
    assert.equal(sync.status, 200, JSON.stringify(sync.data));

    // The platform key never acts for a workspace.
    const refused = await call(
      null,
      { tenant_id: t1, complete: true, users: [] },
      { sub: t1, use: "provision", path: "/integrations/askmira/users/sync" },
    );
    assert.equal(refused.status, 401);
  });

  test("an admin who already has a workspace is asked first", async () => {
    const t2 = crypto.randomUUID();
    const r = await call("provision", company(t2, { admin: { email: "owner@beta.com", name: "Owner" },
      company: { name: "Beta again", slug: "beta2", domain: "beta.com" } }));
    assert.equal(r.status, 409);
    assert.equal(r.data.code, "existing");
    assert.deepEqual(r.data.organizations.map((o) => o.ref), ["beta"]);
    assert.deepEqual(r.data.organizations[0].admins, ["owner@beta.com"]);

    const linked = await call("provision", company(t2, { organization_ref: "beta",
      admin: { email: "owner@beta.com", name: "Owner" } }));
    assert.equal(linked.status, 200, JSON.stringify(linked.data));
    assert.equal(linked.data.external_ref, "beta");
    assert.equal(linked.data.created, false);
    assert.equal(linked.data.organization, "Beta Ltd");
  });

  test("a workspace connected elsewhere can't be attached", async () => {
    const r = await call("provision", company(crypto.randomUUID(), { organization_ref: "beta" }));
    assert.equal(r.status, 409);
    assert.equal(r.data.code, "taken");
  });

  test("search finds workspaces by name or admin email", async () => {
    const byName = await call("organizations", { q: "beta" });
    assert.equal(byName.status, 200);
    assert.ok(byName.data.organizations.some((o) => o.ref === "beta" && o.connected_to));
    const byEmail = await call("organizations", { q: "asha@" });
    assert.ok(byEmail.data.organizations.some((o) => o.name === "Newco Pvt Ltd"));
    assert.equal((await call("organizations", { q: "b" })).status, 422);
  });

  test("a replayed request is refused", async () => {
    const body = JSON.stringify(company(crypto.randomUUID(), { admin: { email: "new@other.com", name: "N" },
      company: { name: "Other", slug: "other", domain: "other.com" } }));
    const token = await sign(PLATFORM, "platform", "platform", body);
    const first = await api.call("POST", "/integrations/askmira/platform/provision", { body, token });
    assert.equal(first.status, 200, JSON.stringify(first.data));
    const again = await api.call("POST", "/integrations/askmira/platform/provision", { body, token });
    assert.equal(again.status, 401);
  });
});
