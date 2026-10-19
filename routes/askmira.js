// The link with AskMira, the HRMS a company may already run its people in.
//
// AskMira is the source of truth for a linked company and its people. It calls
// here server to server to create (or adopt) the tenant and to send who should
// have access, and it sends people here already signed in with a one-time link.
//
// Every request carries a short-lived HS256 token signed with
// ASKMIRA_SHARED_SECRET (aud "askmira:expense", iss "askmira"):
//
//   POST /integrations/askmira/organizations   use=provision, `bh` = SHA-256 of the body
//   POST /integrations/askmira/users/sync      use=provision, `bh` = SHA-256 of the body
//   POST /auth/askmira/exchange                use=launch; each `jti` is accepted once
//
// Employees AskMira manages carry `askmira_user_id`. Only they are switched off
// (`deactivated_at`) when they drop out of AskMira's roster; people added here
// directly are never touched.

const crypto = require("crypto");
const express = require("express");
const { jwtVerify } = require("jose");
const pool = require("../dbClient");
const { signedIn } = require("./auth");
const { normEmail } = require("../middleware/auth");

const AUDIENCE = "askmira:expense";
const ISSUER = "askmira";
const ROLES = new Set(["admin", "employee"]);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const integrationRouter = express.Router();
const authRouter = express.Router();

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function secretKey() {
  const secret = process.env.ASKMIRA_SHARED_SECRET || "";
  // Off (or misconfigured): behave as if the endpoints did not exist.
  if (secret.length < 32) throw httpError(404, "Route not found");
  return new TextEncoder().encode(secret);
}

async function claimsOf(token, use) {
  const key = secretKey();
  let payload;
  try {
    ({ payload } = await jwtVerify(token, key, {
      audience: AUDIENCE,
      issuer: ISSUER,
      algorithms: ["HS256"],
    }));
  } catch {
    throw httpError(401, "This AskMira link is not valid or has expired.");
  }
  if (payload.use !== use) throw httpError(401, "This AskMira link is not valid here.");
  return payload;
}

// AskMira's server-to-server assertion, bound to this exact body.
async function provisionClaims(req) {
  const match = /^Bearer\s+(.+)$/i.exec(req.get("authorization") || "");
  if (!match) {
    secretKey();
    throw httpError(401, "Missing AskMira assertion.");
  }
  const claims = await claimsOf(match[1].trim(), "provision");
  const digest = crypto.createHash("sha256").update(req.rawBody || Buffer.alloc(0)).digest("hex");
  const claimed = String(claims.bh || "");
  if (claimed.length !== digest.length || !crypto.timingSafeEqual(Buffer.from(claimed), Buffer.from(digest))) {
    throw httpError(401, "The assertion does not match this request.");
  }
  if (String(req.body?.tenant_id || "") !== claims.sub) {
    throw httpError(401, "The assertion is for another workspace.");
  }
  return claims;
}

function handle(fn) {
  return async (req, res) => {
    try {
      return res.json(await fn(req));
    } catch (err) {
      if (err.status) return res.status(err.status).json({ error: err.message });
      console.error(`AskMira ${req.method} ${req.originalUrl} error:`, err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  };
}

async function linkedSlug(tenantId) {
  const { rows } = await pool.query(`SELECT slug FROM askmira_links WHERE askmira_tenant_id = $1`, [
    tenantId,
  ]);
  return rows[0]?.slug || null;
}

// ── Organizations ────────────────────────────────────────────────────────────

async function freeSlug(client, wanted) {
  const base = String(wanted || "company").toLowerCase().replace(/[^a-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "") || "company";
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

integrationRouter.post(
  "/organizations",
  handle(async (req) => {
    await provisionClaims(req);
    const tenantId = String(req.body.tenant_id);
    const name = String(req.body.name || "").trim().slice(0, 200) || "Company";
    const domain = String(req.body.domain || "").trim().toLowerCase();

    const existing = await linkedSlug(tenantId);
    if (existing) return { external_ref: existing, adopted: false };

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      let slug = null;
      let adopted = false;
      if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain)) {
        // The company may already use ExpGenie: adopt the tenant whose admins
        // sign in with this domain, unless it is linked to another workspace.
        const { rows } = await client.query(
          `SELECT e.tenant AS slug, l.askmira_tenant_id
             FROM employees e
             LEFT JOIN askmira_links l ON l.slug = e.tenant
            WHERE e.role = 'admin' AND e.tenant IS NOT NULL
              AND LOWER(split_part(e.email, '@', 2)) = $1
            GROUP BY e.tenant, l.askmira_tenant_id`,
          [domain],
        );
        if (rows.length === 1) {
          if (rows[0].askmira_tenant_id) {
            throw httpError(409, "That domain's tenant is linked to another AskMira workspace.");
          }
          slug = rows[0].slug;
          adopted = true;
        }
      }
      if (!slug) {
        slug = await freeSlug(client, req.body.slug);
        await client.query(
          `INSERT INTO tenant_settings (slug, name, plan, status, mrr_amount)
           VALUES ($1, $2, 'growth', 'active', 0)
           ON CONFLICT (slug) DO NOTHING`,
          [slug, name],
        );
      }
      await client.query(`INSERT INTO askmira_links (askmira_tenant_id, slug) VALUES ($1, $2)`, [
        tenantId,
        slug,
      ]);
      await client.query("COMMIT");
      console.log(`[AskMira] tenant ${slug} ${adopted ? "adopted" : "created"} for ${tenantId}`);
      return { external_ref: slug, adopted };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      if (err.code === "23505") throw httpError(409, "This tenant is already linked to another AskMira workspace.");
      throw err;
    } finally {
      client.release();
    }
  }),
);

// ── People ───────────────────────────────────────────────────────────────────

function clean(value, max = 200) {
  if (value == null) return null;
  const text = String(value).trim().slice(0, max);
  return text || null;
}

integrationRouter.post(
  "/users/sync",
  handle(async (req) => {
    await provisionClaims(req);
    const slug = await linkedSlug(String(req.body.tenant_id));
    if (!slug) throw httpError(404, "This workspace is not linked here yet.");
    const people = Array.isArray(req.body.users) ? req.body.users : [];

    let created = 0;
    let updated = 0;
    let deactivated = 0;
    const skipped = [];
    const kept = new Set();

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      for (const person of people) {
        const email = normEmail(person?.email);
        const role = String(person?.role || "");
        if (!EMAIL_RE.test(email)) {
          skipped.push({ email, reason: "not a valid email" });
          continue;
        }
        if (!ROLES.has(role)) {
          skipped.push({ email, reason: `unknown role ${JSON.stringify(role)}` });
          continue;
        }
        const fields = [
          clean(person.name) || email,
          role,
          clean(person.manager_email) ? normEmail(person.manager_email) : null,
          clean(person.department),
          clean(person.employee_code, 64),
          clean(person.grade, 32),
          clean(person.id, 64),
        ];
        const { rows } = await client.query(
          `SELECT email, tenant, role FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
          [email],
        );
        const current = rows[0];
        if (!current) {
          await client.query(
            `INSERT INTO employees
               (email, name, role, manager_email, department, employee_id, grade, askmira_user_id, tenant)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
            [email, ...fields, slug],
          );
          created++;
          kept.add(email);
          continue;
        }
        if (current.role === "super_admin") {
          skipped.push({ email, reason: "an ExpGenie super admin" });
          continue;
        }
        if (current.tenant !== slug) {
          skipped.push({ email, reason: "belongs to another workspace in ExpGenie" });
          continue;
        }
        kept.add(email);
        const result = await client.query(
          `UPDATE employees
              SET name = $2, role = $3, manager_email = $4, department = $5,
                  employee_id = COALESCE($6, employee_id), grade = COALESCE($7, grade),
                  askmira_user_id = $8, deactivated_at = NULL, updated_at = NOW()
            WHERE LOWER(email) = LOWER($1)
              AND (name IS DISTINCT FROM $2 OR role IS DISTINCT FROM $3
                   OR manager_email IS DISTINCT FROM $4 OR department IS DISTINCT FROM $5
                   OR ($6::text IS NOT NULL AND employee_id IS DISTINCT FROM $6)
                   OR ($7::text IS NOT NULL AND grade IS DISTINCT FROM $7)
                   OR askmira_user_id IS DISTINCT FROM $8 OR deactivated_at IS NOT NULL)`,
          [email, ...fields],
        );
        updated += result.rowCount;
      }
      if (req.body.complete !== false) {
        const { rows: managed } = await client.query(
          `SELECT email FROM employees
            WHERE tenant = $1 AND askmira_user_id IS NOT NULL AND deactivated_at IS NULL`,
          [slug],
        );
        const leavers = managed.map((r) => r.email).filter((e) => !kept.has(normEmail(e)));
        if (leavers.length) {
          const result = await client.query(
            `UPDATE employees SET deactivated_at = NOW(), updated_at = NOW()
              WHERE tenant = $1 AND email = ANY($2::text[])`,
            [slug, leavers],
          );
          deactivated = result.rowCount;
        }
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
    console.log(
      `[AskMira] roster for ${slug}: ${created} created, ${updated} updated, ${deactivated} deactivated, ${skipped.length} skipped`,
    );
    return { created, updated, deactivated, skipped };
  }),
);

// ── Sign-in from AskMira ─────────────────────────────────────────────────────

authRouter.post("/exchange", async (req, res) => {
  try {
    const claims = await claimsOf(String(req.body?.token || ""), "launch");
    if (!claims.jti || typeof claims.exp !== "number") throw httpError(401, "This AskMira link is not valid.");

    await pool.query(`DELETE FROM askmira_launches WHERE expires_at < NOW() - INTERVAL '5 minutes'`);
    const used = await pool.query(
      `INSERT INTO askmira_launches (jti, expires_at) VALUES ($1, to_timestamp($2))
       ON CONFLICT (jti) DO NOTHING`,
      [String(claims.jti).slice(0, 64), claims.exp],
    );
    if (!used.rowCount) throw httpError(401, "This sign-in link was already used. Open it again from AskMira.");

    const slug = await linkedSlug(String(claims.tid || ""));
    if (!slug || (claims.ext && String(claims.ext) !== slug)) {
      throw httpError(403, "Your company is not linked to ExpGenie.");
    }
    const email = normEmail(claims.email);
    const role = String(claims.role || "");
    if (!EMAIL_RE.test(email) || !ROLES.has(role)) {
      throw httpError(403, "AskMira did not give you a role in ExpGenie.");
    }

    const { rows } = await pool.query(`SELECT * FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`, [
      email,
    ]);
    let employee = rows[0];
    if (!employee) {
      // Joined since the last sync: let them in now; the next sync fills in the rest.
      ({ rows: [employee] } = await pool.query(
        `INSERT INTO employees (email, name, role, tenant, askmira_user_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING *`,
        [email, clean(claims.name) || email, role, slug, clean(claims.sub, 64)],
      ));
    } else {
      if (employee.role === "super_admin" || employee.tenant !== slug) {
        throw httpError(409, "This email already has an ExpGenie account in another workspace.");
      }
      if (employee.deactivated_at) throw httpError(403, "Your ExpGenie account has been switched off.");
      ({ rows: [employee] } = await pool.query(
        `UPDATE employees SET role = $2, askmira_user_id = $3, updated_at = NOW()
          WHERE LOWER(email) = LOWER($1) RETURNING *`,
        [email, role, clean(claims.sub, 64)],
      ));
    }
    console.log(`[AskMira] ${email} signed in from AskMira (${slug})`);
    return await signedIn(res, employee);
  } catch (err) {
    if (err.status) return res.status(err.status).json({ error: err.message });
    console.error("POST /auth/askmira/exchange error:", err);
    return res.status(500).json({ error: "Sign-in failed" });
  }
});

module.exports = { integrationRouter, authRouter };
