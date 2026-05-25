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

const router = express.Router();

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
      name: prettyName(r.slug),
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
         COALESCE(ts.plan, 'growth')                           AS plan,
         COALESCE(ts.status, 'active')                         AS status,
         COALESCE(ts.mrr_amount, 0)::float                     AS mrr_amount
       FROM employees e
       LEFT JOIN tenant_settings ts ON ts.slug = e.tenant
       WHERE e.tenant = $1
       GROUP BY e.tenant, ts.plan, ts.status, ts.mrr_amount`,
      [req.params.slug],
    );
    if (!rows.length) return res.status(404).json({ error: "Tenant not found" });
    const r = rows[0];
    return res.json({
      id: r.slug,
      slug: r.slug,
      name: prettyName(r.slug),
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

module.exports = router;
