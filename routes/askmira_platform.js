// AskMira's platform sets a company up here (AskMira → Platform → Connected tools).
//
// AskMira's super admin holds ExpenseGenie's platform key, the same value as
// ASKMIRA_PLATFORM_SECRET here. With it — never with a workspace's own secret —
// AskMira may:
//
//   POST /integrations/askmira/platform/ping           check the key
//   POST /integrations/askmira/platform/organizations  find a workspace here
//   POST /integrations/askmira/platform/provision      create or attach one
//
// Each carries an HS256 token (aud "askmira:expense", iss "askmira", sub and use
// "platform", `bh` = SHA-256 of the body). `provision` creates a workspace with
// AskMira's admin as its admin (they come in from AskMira, or set a password
// with "Forgot password"), or attaches the workspace the super admin picked,
// and answers with that workspace's own secret, exactly as Allow does
// (routes/askmira.js), so every later call is checked with it.
//
// It never makes a second workspace for someone who already has an account
// here, or for a domain whose admins already have one, unasked: it answers 409
// "existing" naming them, and the super admin links that one or says
// "create_new".

const crypto = require("crypto");
const express = require("express");
const { jwtVerify } = require("jose");
const pool = require("../dbClient");
const { normEmail } = require("../middleware/auth");

const AUDIENCE = "askmira:expense";
const ISSUER = "askmira";
const PRODUCT = "expense";
const BRAND = "ExpenseGenie";
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DOMAIN_RE = /^[a-z0-9.-]+\.[a-z]{2,}$/;

const router = express.Router();

function httpError(status, message, extra = {}) {
  const err = new Error(message);
  err.status = status;
  err.extra = extra;
  return err;
}

function serverKey() {
  return process.env.AUTH_JWT_SECRET || "";
}

// The same derivation as routes/askmira.js: a workspace's secret from its nonce.
function derive(slug, nonce) {
  return crypto.createHmac("sha256", serverKey()).update(`askmira-org:v1:${slug}:${nonce}`).digest("hex");
}

function clean(value, max = 200) {
  if (value == null) return null;
  const text = String(value).trim().slice(0, max);
  return text || null;
}

function obj(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

async function platformClaims(req) {
  const key = process.env.ASKMIRA_PLATFORM_SECRET || "";
  // Off: as if these endpoints did not exist.
  if (key.length < 32) throw httpError(404, "Route not found");
  const match = /^Bearer\s+(.+)$/i.exec(req.get("authorization") || "");
  if (!match) throw httpError(401, "Missing AskMira assertion.");
  let payload;
  try {
    ({ payload } = await jwtVerify(match[1].trim(), new TextEncoder().encode(key), {
      audience: AUDIENCE,
      issuer: ISSUER,
      algorithms: ["HS256"],
    }));
  } catch {
    throw httpError(401, "This AskMira platform key is not the one set here.");
  }
  if (payload.use !== "platform" || payload.sub !== "platform") {
    throw httpError(401, "This AskMira platform key is not the one set here.");
  }
  const digest = crypto.createHash("sha256").update(req.rawBody || Buffer.alloc(0)).digest("hex");
  const claimed = String(payload.bh || "");
  if (claimed.length !== digest.length || !crypto.timingSafeEqual(Buffer.from(claimed), Buffer.from(digest))) {
    throw httpError(401, "The assertion does not match this request.");
  }
  return payload;
}

// A captured request can't be sent again to swap the key AskMira holds.
async function spendOnce(claims) {
  if (!claims.jti || typeof claims.exp !== "number") throw httpError(401, "This AskMira request is not valid.");
  await pool.query(`DELETE FROM askmira_launches WHERE expires_at < NOW() - INTERVAL '5 minutes'`);
  const { rowCount } = await pool.query(
    `INSERT INTO askmira_launches (jti, expires_at) VALUES ($1, to_timestamp($2)) ON CONFLICT DO NOTHING`,
    [String(claims.jti).slice(0, 64), claims.exp],
  );
  if (!rowCount) throw httpError(401, "This request was already carried out.");
}

/** Each workspace: its name, its admins, and the AskMira workspace it is connected to. */
async function describe(slugs) {
  if (!slugs.length) return [];
  const { rows } = await pool.query(
    `SELECT s.slug, COALESCE(t.name, s.slug) AS name, l.askmira_tenant_id,
            COALESCE(array_agg(LOWER(e.email) ORDER BY e.email)
                     FILTER (WHERE e.email IS NOT NULL), '{}') AS admins
       FROM UNNEST($1::text[]) AS s(slug)
       LEFT JOIN tenant_settings t ON t.slug = s.slug
       LEFT JOIN askmira_links l ON l.slug = s.slug
       LEFT JOIN employees e ON e.tenant = s.slug AND e.role = 'admin' AND e.deactivated_at IS NULL
      GROUP BY s.slug, t.name, l.askmira_tenant_id
      ORDER BY LOWER(COALESCE(t.name, s.slug))`,
    [slugs],
  );
  return rows.map((r) => ({
    ref: r.slug,
    name: r.name,
    admins: r.admins.slice(0, 5),
    connected_to: r.askmira_tenant_id || null,
  }));
}

async function organizations(body) {
  const q = clean(body.q, 120);
  if (!q || q.length < 2) throw httpError(422, "Type at least two letters.");
  const like = `%${q.replace(/[%_\\]/g, (c) => `\\${c}`)}%`;
  const { rows } = await pool.query(
    `SELECT slug FROM (
        SELECT slug FROM tenant_settings WHERE name ILIKE $1 OR slug ILIKE $1
        UNION
        SELECT tenant AS slug FROM employees
         WHERE tenant IS NOT NULL AND role = 'admin' AND email ILIKE $1
     ) found LIMIT 20`,
    [like],
  );
  return { organizations: await describe(rows.map((r) => r.slug)) };
}

async function freeSlug(client, wanted) {
  const base =
    String(wanted || "company").toLowerCase().replace(/[^a-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "") || "company";
  for (let n = 1; n < 1000; n++) {
    const slug = n === 1 ? base : `${base}-${n}`;
    const taken = await client.query(
      `SELECT 1 FROM employees WHERE tenant = $1
        UNION SELECT 1 FROM tenant_settings WHERE slug = $1
        UNION SELECT 1 FROM askmira_links WHERE slug = $1
        LIMIT 1`,
      [slug],
    );
    if (!taken.rows.length) return slug;
  }
  throw httpError(409, "Could not find a free workspace address.");
}

/** Connect the workspace to that AskMira workspace: a fresh nonce, so a fresh secret. */
async function connect(client, slug, askmira) {
  const nonce = crypto.randomBytes(32).toString("base64url");
  // One AskMira workspace per workspace here, and the other way round.
  await client.query(`DELETE FROM askmira_links WHERE askmira_tenant_id = $1 OR slug = $2`, [askmira.id, slug]);
  await client.query(
    `INSERT INTO askmira_links (askmira_tenant_id, slug, secret_nonce, askmira_name, askmira_origin, connected_at, connected_by)
     VALUES ($1, $2, $3, $4, $5, NOW(), 'askmira-platform')`,
    [askmira.id, slug, nonce, askmira.name, askmira.origin],
  );
  return derive(slug, nonce);
}

function originOf(value) {
  try {
    const url = new URL(String(value || ""));
    return ["https:", "http:"].includes(url.protocol) ? url.origin : null;
  } catch {
    return null;
  }
}

async function nameOf(client, slug) {
  const { rows } = await client.query(`SELECT name FROM tenant_settings WHERE slug = $1`, [slug]);
  return rows[0]?.name || slug;
}

async function provision(body, claims) {
  if (serverKey().length < 32) throw httpError(409, "Set a long AUTH_JWT_SECRET on this server first.");
  await spendOnce(claims);
  const tenantId = String(body.tenant_id || "").toLowerCase();
  const company = obj(body.company);
  const admin = obj(body.admin);
  const name = clean(company.name) || clean(body.tenant_name);
  const email = normEmail(admin.email);
  const ref = clean(body.organization_ref, 120);
  if (!UUID_RE.test(tenantId) || !name || !EMAIL_RE.test(email)) {
    throw httpError(422, "AskMira sent an incomplete company.");
  }
  const askmira = { id: tenantId, name: clean(body.tenant_name) || name, origin: originOf(body.askmira_origin) };
  const domain = String(company.domain || "").trim().toLowerCase();
  const answer = (slug, secret, organization, created, adminCreated) => ({
    product: PRODUCT,
    brand: BRAND,
    secret,
    external_ref: slug,
    organization,
    created,
    admin_created: adminCreated,
  });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Attach the workspace the super admin picked.
    if (ref) {
      const { rows } = await client.query(
        `SELECT $1::text AS slug
          WHERE EXISTS (SELECT 1 FROM tenant_settings WHERE slug = $1)
             OR EXISTS (SELECT 1 FROM employees WHERE tenant = $1)`,
        [ref],
      );
      if (!rows.length) throw httpError(404, `No such workspace in ${BRAND}.`);
      const { rows: link } = await client.query(`SELECT askmira_tenant_id FROM askmira_links WHERE slug = $1`, [ref]);
      if (link[0] && link[0].askmira_tenant_id !== tenantId) {
        throw httpError(409, `${ref} is connected to another AskMira workspace.`, { code: "taken" });
      }
      const secret = await connect(client, ref, askmira);
      const organization = await nameOf(client, ref);
      await client.query("COMMIT");
      console.log(`[AskMira] platform attached ${ref} to workspace ${tenantId}`);
      return answer(ref, secret, organization, false, false);
    }

    // Already connected here (AskMira lost its key, or asked twice): the same workspace, a new key.
    const { rows: linked } = await client.query(`SELECT slug FROM askmira_links WHERE askmira_tenant_id = $1`, [
      tenantId,
    ]);
    if (linked[0]) {
      const secret = await connect(client, linked[0].slug, askmira);
      const organization = await nameOf(client, linked[0].slug);
      await client.query("COMMIT");
      return answer(linked[0].slug, secret, organization, false, false);
    }

    const { rows: users } = await client.query(`SELECT email, tenant, role FROM employees WHERE LOWER(email) = $1`, [
      email,
    ]);
    const user = users[0] || null;
    if (body.create_new !== true) {
      const slugs = new Set();
      if (user?.tenant) slugs.add(user.tenant);
      if (DOMAIN_RE.test(domain)) {
        const { rows } = await client.query(
          `SELECT DISTINCT tenant FROM employees
            WHERE role = 'admin' AND tenant IS NOT NULL AND LOWER(split_part(email, '@', 2)) = $1`,
          [domain],
        );
        rows.forEach((r) => slugs.add(r.tenant));
      }
      if (slugs.size) {
        const who = user ? `${email} already has an account` : `${domain} already has a workspace`;
        throw httpError(409, `${who} in ${BRAND}.`, {
          code: "existing",
          organizations: await describe([...slugs].slice(0, 10)),
        });
      }
    }

    const slug = await freeSlug(client, company.slug || name);
    await client.query(
      `INSERT INTO tenant_settings (slug, name, plan, status, mrr_amount)
       VALUES ($1, $2, 'growth', 'active', 0)`,
      [slug, name],
    );
    let adminCreated = false;
    if (!user) {
      // No password: they come in from AskMira, or set one with "Forgot password".
      await client.query(
        `INSERT INTO employees (email, name, role, tenant, askmira_user_id)
         VALUES ($1, $2, 'admin', $3, 'askmira-platform')`,
        [email, clean(admin.name) || email, slug],
      );
      adminCreated = true;
    }
    const secret = await connect(client, slug, askmira);
    await client.query("COMMIT");
    console.log(`[AskMira] platform created ${slug} for workspace ${tenantId}, admin ${email}`);
    return answer(slug, secret, name, true, adminCreated);
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

router.post("/:action", async (req, res) => {
  try {
    const claims = await platformClaims(req);
    const body = obj(req.body);
    let out;
    if (req.params.action === "ping") {
      const ready = serverKey().length >= 32;
      out = {
        product: PRODUCT,
        brand: BRAND,
        ready,
        message: ready ? `${BRAND} is ready.` : "Set a long AUTH_JWT_SECRET on this server first.",
      };
    } else if (req.params.action === "organizations") {
      out = await organizations(body);
    } else if (req.params.action === "provision") {
      out = await provision(body, claims);
    } else {
      throw httpError(404, "Route not found");
    }
    return res.json(out);
  } catch (err) {
    if (err.status) return res.status(err.status).json({ ...(err.extra || {}), error: err.message });
    console.error(`AskMira platform ${req.params.action} error:`, err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

module.exports = { platformRouter: router };
