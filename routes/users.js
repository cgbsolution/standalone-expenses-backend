// Employee directory — reads the `employees` table.
//
// Endpoints:
//   GET /users                       → all users (super-admin scope)
//   GET /users?tenant=xeltrion       → users in a tenant (admin scope)
//   GET /users?role=admin            → users with a role (combinable with tenant)
//   GET /users/:email                → one user
//
// Trust-client pattern: matches the existing /master-expense routes, which
// already accept caller-provided email/tenant params. Replace with a JWT-based
// guard when token issuance lands in /auth.

const express = require("express");
const pool = require("../dbClient");
const { safeNotify } = require("../notifier");
const { createResetToken, buildResetUrl, INVITE_TTL_HOURS } = require("../utils/passwordTokens");

const router = express.Router();

function rowToUser(row) {
  const name = row.name || "";
  const parts = name.trim().split(/\s+/);
  const role = (row.role || "employee").toLowerCase();
  const tenantSlug = role === "super_admin" ? null : row.tenant || null;
  return {
    id: row.employee_id || row.email,
    email: row.email,
    displayName: name,
    givenName: parts[0] || "",
    surname: parts.slice(1).join(" "),
    grade: row.grade,
    managerEmail: row.manager_email,
    financeManagerEmail: row.finance_manager_email,
    employeeId: row.employee_id,
    department: row.department,
    companyCode: row.company_code,
    vendorCode: row.vendor_code,
    costCenter: row.cost_center,
    sectionCode: row.section_code,
    role,
    tenant: tenantSlug,
    tenantSlug,
    authProvider: "local",
    createdAt: row.created_at,
  };
}

/**
 * @swagger
 * /users:
 *   get:
 *     summary: List employees with optional tenant/role filters
 *     tags: [Users]
 *     parameters:
 *       - in: query
 *         name: tenant
 *         schema: { type: string }
 *       - in: query
 *         name: role
 *         schema: { type: string, enum: [super_admin, admin, employee] }
 *       - in: query
 *         name: q
 *         schema: { type: string, description: "Search by name or email (ILIKE)" }
 *     responses:
 *       200: { description: List of users }
 */
router.get("/", async (req, res) => {
  const { tenant, role, q } = req.query;
  const filters = [];
  const params = [];

  if (tenant) {
    params.push(tenant);
    filters.push(`tenant = $${params.length}`);
  }
  if (role) {
    params.push(role);
    filters.push(`role = $${params.length}`);
  }
  if (q) {
    params.push(`%${q}%`);
    filters.push(`(name ILIKE $${params.length} OR email ILIKE $${params.length})`);
  }

  const where = filters.length ? `WHERE ${filters.join(" AND ")}` : "";

  try {
    const { rows } = await pool.query(
      `SELECT * FROM employees ${where} ORDER BY name ASC`,
      params,
    );
    return res.json(rows.map(rowToUser));
  } catch (err) {
    console.error("GET /users error:", err);
    return res.status(500).json({ error: "Failed to fetch users" });
  }
});

/**
 * @swagger
 * /users/{email}:
 *   get:
 *     summary: Get one user by email
 *     tags: [Users]
 */
router.get("/:email", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [req.params.email],
    );
    if (!rows.length) return res.status(404).json({ error: "Not found" });
    return res.json(rowToUser(rows[0]));
  } catch (err) {
    console.error("GET /users/:email error:", err);
    return res.status(500).json({ error: "Failed to fetch user" });
  }
});

// Allow-list of fields a tenant admin can update via PUT /users/:email.
// `email`, `tenant`, `password_hash`, `created_at`, `updated_at` are intentionally
// excluded: those are identity / system-managed.
const UPDATABLE_FIELDS = {
  displayName: "name",
  department: "department",
  grade: "grade",
  managerEmail: "manager_email",
  financeManagerEmail: "finance_manager_email",
  employeeId: "employee_id",
  companyCode: "company_code",
  vendorCode: "vendor_code",
  costCenter: "cost_center",
  sectionCode: "section_code",
  role: "role",
};
const ALLOWED_ROLES = new Set(["admin", "employee"]);

/**
 * @swagger
 * /users/{email}:
 *   put:
 *     summary: Update an employee's profile (admin-only fields)
 *     tags: [Users]
 *     parameters:
 *       - in: path
 *         name: email
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               displayName: { type: string }
 *               department: { type: string }
 *               grade: { type: string }
 *               managerEmail: { type: string }
 *               financeManagerEmail: { type: string }
 *               employeeId: { type: string }
 *               companyCode: { type: string }
 *               vendorCode: { type: string }
 *               costCenter: { type: string }
 *               sectionCode: { type: string }
 *               role: { type: string, enum: [employee, admin] }
 *     responses:
 *       200: { description: Updated user }
 *       400: { description: Invalid input }
 *       403: { description: Cannot edit a super-admin via this endpoint }
 *       404: { description: User not found }
 */
router.put("/:email", async (req, res) => {
  try {
    const { rows: existingRows } = await pool.query(
      `SELECT * FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [req.params.email],
    );
    if (!existingRows.length) return res.status(404).json({ error: "User not found" });
    const existing = existingRows[0];

    // Refuse to mutate a super-admin row via the tenant-admin path. Promotions
    // and demotions of super-admins need a separate, audited flow.
    if (existing.role === "super_admin") {
      return res.status(403).json({ error: "Super-admin profiles can't be edited here" });
    }

    const body = req.body || {};
    const setExpressions = [];
    const values = [];
    let i = 1;

    for (const [apiKey, column] of Object.entries(UPDATABLE_FIELDS)) {
      if (!Object.prototype.hasOwnProperty.call(body, apiKey)) continue;
      let value = body[apiKey];

      if (apiKey === "role") {
        if (typeof value === "string") value = value.toLowerCase();
        if (!ALLOWED_ROLES.has(value)) {
          return res
            .status(400)
            .json({ error: `role must be one of: ${[...ALLOWED_ROLES].join(", ")}` });
        }
      }
      if (typeof value === "string") value = value.trim();
      if (value === "") value = null;

      setExpressions.push(`${column} = $${i++}`);
      values.push(value);
    }

    if (setExpressions.length === 0) {
      return res.status(400).json({ error: "No updatable fields provided" });
    }

    values.push(req.params.email);
    const sql = `UPDATE employees
                    SET ${setExpressions.join(", ")},
                        updated_at = NOW()
                  WHERE LOWER(email) = LOWER($${i})
              RETURNING *`;

    const { rows: updatedRows } = await pool.query(sql, values);
    return res.json(rowToUser(updatedRows[0]));
  } catch (err) {
    console.error("PUT /users/:email error:", err);
    return res.status(500).json({ error: "Failed to update user" });
  }
});

/**
 * @swagger
 * /users:
 *   post:
 *     summary: Create (invite) an employee in a tenant
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [tenantSlug, email, displayName, role]
 *             properties:
 *               tenantSlug:   { type: string }
 *               email:        { type: string }
 *               displayName:  { type: string }
 *               role:         { type: string, enum: [employee, admin] }
 *               department:   { type: string }
 *               employeeId:   { type: string }
 *               managerEmail: { type: string }
 *     responses:
 *       201: { description: Created user }
 *       400: { description: Invalid input }
 *       409: { description: Email already in use }
 */
router.post("/", async (req, res) => {
  const body = req.body || {};
  const tenantSlug = String(body.tenantSlug || "").trim().toLowerCase();
  const email = String(body.email || "").trim().toLowerCase();
  const displayName = String(body.displayName || "").trim();
  const role = String(body.role || "employee").toLowerCase();
  const department = body.department ? String(body.department).trim() : null;
  const employeeId = body.employeeId ? String(body.employeeId).trim() : null;
  const managerEmail = body.managerEmail ? String(body.managerEmail).trim().toLowerCase() : null;

  if (!tenantSlug) return res.status(400).json({ error: "tenantSlug is required" });
  if (!displayName) return res.status(400).json({ error: "displayName is required" });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "A valid email is required" });
  }
  if (!ALLOWED_ROLES.has(role)) {
    return res.status(400).json({ error: `role must be one of: ${[...ALLOWED_ROLES].join(", ")}` });
  }

  try {
    const clash = await pool.query(
      `SELECT 1 FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [email],
    );
    if (clash.rows.length) {
      return res.status(409).json({ error: "Someone with that email is already on the team" });
    }

    // No password is set: the invitee gets an email to choose their own.
    const { rows } = await pool.query(
      `INSERT INTO employees
         (email, name, role, tenant, department, employee_id, manager_email)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [email, displayName, role, tenantSlug, department, employeeId, managerEmail],
    );
    const user = rowToUser(rows[0]);

    // Best-effort "set your password" link + email; also returned so an admin
    // can share it manually when email delivery isn't configured.
    let inviteUrl = null;
    try {
      const token = await createResetToken(email, INVITE_TTL_HOURS);
      inviteUrl = buildResetUrl(token);
      safeNotify("account.invite", {
        recipient: email,
        name: displayName,
        tenantName: tenantSlug,
        intro: `You've been invited to join ${tenantSlug} on ExpGenie. Click below to create your password and sign in. This link expires in 3 days.`,
        ctaLabel: "Set your password",
        actionUrl: inviteUrl,
      });
    } catch (mailErr) {
      console.error("POST /users invite-link error:", mailErr);
    }

    return res.status(201).json({ ...user, inviteUrl });
  } catch (err) {
    console.error("POST /users error:", err);
    return res.status(500).json({ error: "Failed to create user" });
  }
});

module.exports = router;
