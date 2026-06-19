// Tenant directory — derived live from the `employees` and `expenses` tables.
//
// A "tenant" is any distinct value of `employees.tenant` (excluding NULL, which
// is reserved for super-admins). Aggregate stats are computed at query time:
//   - userCount: COUNT(*) of employees in that tenant
//   - adminEmail: an employee with role='admin' (if any)
//   - createdAt: MIN(employees.created_at) — the first row seeded for that tenant
//   - monthlyExpenseVolume: SUM of expenses submitted in the last 30 days
//     by users in that tenant
//
// No tenants table exists yet; this view is intentionally schema-less so adding
// a real tenants table later is a drop-in replacement.

const express = require("express");
const pool = require("../dbClient");
const { safeNotify } = require("../notifier");
const { createResetToken, buildResetUrl, INVITE_TTL_HOURS } = require("../utils/passwordTokens");

const router = express.Router();

// Monthly recurring revenue per plan tier — mirrors the pricing shown in the
// dashboard's "Create a tenant" form.
const PLAN_MRR = { starter: 0, growth: 800, scale: 2400, enterprise: 6200 };
const VALID_PLANS = new Set(Object.keys(PLAN_MRR));

/**
 * @swagger
 * /tenants:
 *   get:
 *     summary: List tenants with per-tenant aggregates
 *     tags: [Tenants]
 *     responses:
 *       200: { description: Array of tenants }
 */
router.get("/", async (_req, res) => {
  try {
    const { rows } = await pool.query(`
      WITH t AS (
        SELECT
          tenant                                              AS slug,
          COUNT(*)::int                                        AS user_count,
          MIN(created_at)                                      AS created_at,
          (
            SELECT email FROM employees e2
             WHERE e2.tenant = e1.tenant AND e2.role = 'admin'
             ORDER BY created_at ASC
             LIMIT 1
          )                                                    AS admin_email,
          (
            SELECT name FROM employees e3
             WHERE e3.tenant = e1.tenant AND e3.role = 'admin'
             ORDER BY created_at ASC
             LIMIT 1
          )                                                    AS admin_name
        FROM employees e1
        WHERE tenant IS NOT NULL AND tenant <> '' AND role <> 'super_admin'
        GROUP BY tenant
      ),
      v AS (
        SELECT
          ee.tenant                                            AS slug,
          COALESCE(SUM((ex.data->>'TotalAmount')::numeric), 0) AS volume
        FROM employees ee
        LEFT JOIN expenses ex
          ON ex.submitter_email = ee.email
         AND ex.created_at > NOW() - INTERVAL '30 days'
        GROUP BY ee.tenant
      )
      SELECT
        t.slug,
        t.user_count,
        t.created_at,
        t.admin_email,
        t.admin_name,
        COALESCE(v.volume, 0)::float AS monthly_expense_volume,
        ts.name                       AS name,
        COALESCE(ts.plan, 'growth')   AS plan,
        COALESCE(ts.status, 'active') AS status,
        COALESCE(ts.mrr_amount, 0)::float AS mrr_amount
      FROM t
      LEFT JOIN v              ON v.slug  = t.slug
      LEFT JOIN tenant_settings ts ON ts.slug = t.slug
      ORDER BY t.user_count DESC
    `);

    const tenants = rows.map((r) => ({
      id: r.slug,
      slug: r.slug,
      name: r.name || prettyName(r.slug),
      plan: r.plan,
      status: r.status,
      userCount: r.user_count,
      monthlyExpenseVolume: Number(r.monthly_expense_volume),
      mrr: Number(r.mrr_amount),
      createdAt: r.created_at,
      adminEmail: r.admin_email,
      adminName: r.admin_name,
    }));
    return res.json(tenants);
  } catch (err) {
    console.error("GET /tenants error:", err);
    return res.status(500).json({ error: "Failed to fetch tenants" });
  }
});

/**
 * @swagger
 * /tenants/{slug}:
 *   get:
 *     summary: One tenant
 *     tags: [Tenants]
 */
router.get("/:slug", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT
         e.tenant                                             AS slug,
         COUNT(*)::int                                         AS user_count,
         MIN(e.created_at)                                     AS created_at,
         (SELECT email FROM employees WHERE tenant = $1 AND role = 'admin' ORDER BY created_at ASC LIMIT 1) AS admin_email,
         (SELECT name  FROM employees WHERE tenant = $1 AND role = 'admin' ORDER BY created_at ASC LIMIT 1) AS admin_name,
         ts.name                                               AS name,
         COALESCE(ts.plan, 'growth')                           AS plan,
         COALESCE(ts.status, 'active')                         AS status,
         COALESCE(ts.mrr_amount, 0)::float                     AS mrr_amount
       FROM employees e
       LEFT JOIN tenant_settings ts ON ts.slug = e.tenant
       WHERE e.tenant = $1
       GROUP BY e.tenant, ts.name, ts.plan, ts.status, ts.mrr_amount`,
      [req.params.slug],
    );
    if (!rows.length) return res.status(404).json({ error: "Tenant not found" });
    const r = rows[0];
    return res.json({
      id: r.slug,
      slug: r.slug,
      name: r.name || prettyName(r.slug),
      plan: r.plan,
      status: r.status,
      userCount: r.user_count,
      monthlyExpenseVolume: 0,
      mrr: Number(r.mrr_amount),
      createdAt: r.created_at,
      adminEmail: r.admin_email,
      adminName: r.admin_name,
    });
  } catch (err) {
    console.error("GET /tenants/:slug error:", err);
    return res.status(500).json({ error: "Failed to fetch tenant" });
  }
});

function prettyName(slug) {
  if (!slug) return "Unnamed tenant";
  return slug
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/**
 * @swagger
 * /tenants:
 *   post:
 *     summary: Create a tenant (provisions its first admin employee)
 *     tags: [Tenants]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, adminName, adminEmail, plan]
 *             properties:
 *               name:            { type: string }
 *               customSubdomain: { type: string }
 *               adminName:       { type: string }
 *               adminEmail:      { type: string }
 *               plan:            { type: string, enum: [starter, growth, scale, enterprise] }
 *     responses:
 *       201: { description: Tenant created }
 *       400: { description: Invalid input }
 *       409: { description: Subdomain or admin email already in use }
 */
router.post("/", async (req, res) => {
  const body = req.body || {};
  const name = String(body.name || "").trim();
  const adminName = String(body.adminName || "").trim();
  const adminEmail = String(body.adminEmail || "").trim().toLowerCase();
  const plan = String(body.plan || "growth").toLowerCase();
  let slug = String(body.customSubdomain || "").trim().toLowerCase();
  if (!slug) {
    slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  }

  if (!name) return res.status(400).json({ error: "Company name is required" });
  if (!adminName) return res.status(400).json({ error: "Admin name is required" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(adminEmail)) {
    return res.status(400).json({ error: "A valid admin email is required" });
  }
  if (!slug || !/^[a-z0-9.-]+$/.test(slug)) {
    return res
      .status(400)
      .json({ error: "Subdomain may contain only lowercase letters, digits, dots and dashes" });
  }
  if (!VALID_PLANS.has(plan)) {
    return res.status(400).json({ error: `plan must be one of: ${[...VALID_PLANS].join(", ")}` });
  }

  const mrr = PLAN_MRR[plan];
  const status = "trialing";
  const client = await pool.connect();
  let createdAt;
  try {
    // A tenant "exists" once an employee row carries its slug — so the slug is
    // taken if anyone already belongs to it.
    const slugTaken = await client.query(`SELECT 1 FROM employees WHERE tenant = $1 LIMIT 1`, [slug]);
    if (slugTaken.rows.length) {
      return res.status(409).json({ error: `Subdomain "${slug}" is already taken` });
    }
    const emailTaken = await client.query(
      `SELECT 1 FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [adminEmail],
    );
    if (emailTaken.rows.length) {
      return res.status(409).json({ error: "An account with that admin email already exists" });
    }

    await client.query("BEGIN");

    // 1. The tenant's first admin — this row is what makes the tenant real.
    //    No password is set: the admin gets an email to choose their own.
    const { rows: empRows } = await client.query(
      `INSERT INTO employees (email, name, role, tenant)
       VALUES ($1, $2, 'admin', $3)
       RETURNING created_at`,
      [adminEmail, adminName, slug],
    );

    // 2. Plan / billing settings, including the company display name.
    await client.query(
      `INSERT INTO tenant_settings (slug, name, plan, status, mrr_amount)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (slug) DO UPDATE SET
         name       = EXCLUDED.name,
         plan       = EXCLUDED.plan,
         status     = EXCLUDED.status,
         mrr_amount = EXCLUDED.mrr_amount,
         updated_at = NOW()`,
      [slug, name, plan, status, mrr],
    );

    await client.query("COMMIT");
    createdAt = empRows[0].created_at;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("POST /tenants error:", err);
    return res.status(500).json({ error: "Failed to create tenant" });
  } finally {
    client.release();
  }

  // Tenant exists now. Best-effort "set your password" link + email — an email
  // hiccup must never fail a created tenant. The link is also returned so the
  // super-admin can share it manually when email delivery isn't configured.
  let inviteUrl = null;
  try {
    const token = await createResetToken(adminEmail, INVITE_TTL_HOURS);
    inviteUrl = buildResetUrl(token);
    safeNotify("account.invite", {
      recipient: adminEmail,
      name: adminName,
      tenantName: name,
      intro: `You've been set up as the admin for ${name} on ExpGenie. Click below to create your password and sign in. This link expires in 3 days.`,
      ctaLabel: "Set your password",
      actionUrl: inviteUrl,
    });
  } catch (err) {
    console.error("POST /tenants invite-link error:", err);
  }

  return res.status(201).json({
    id: slug,
    slug,
    name,
    plan,
    status,
    userCount: 1,
    monthlyExpenseVolume: 0,
    mrr,
    createdAt,
    customSubdomain: slug,
    adminEmail,
    adminName,
    inviteUrl,
  });
});

module.exports = router;
