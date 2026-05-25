const express = require("express");
const bcrypt = require("bcryptjs");
const pool = require("../dbClient");

const router = express.Router();

function rowToUser(row) {
  const name = row.name || "";
  const parts = name.trim().split(/\s+/);
  const role = (row.role || "employee").toLowerCase();
  // Super-admins live outside any tenant; everyone else inherits the row's tenant.
  const tenantSlug = role === "super_admin" ? null : row.tenant || null;
  return {
    id: row.employee_id || row.email,
    email: row.email,
    mail: row.email,
    userPrincipalName: row.email,
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
  };
}

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Local email + password sign-in against the employees table
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email: { type: string }
 *               password: { type: string }
 *     responses:
 *       200: { description: Login OK }
 *       400: { description: Missing fields }
 *       401: { description: Invalid email or password }
 *       500: { description: Login failed }
 */
router.post("/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const { rows } = await pool.query(
      `SELECT * FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [email]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "User does not exist" });
    }

    const employee = rows[0];

    if (!employee.password_hash) {
      return res.status(401).json({
        error: "No password set for this account. Run `npm run seed:passwords` on the backend.",
      });
    }

    const ok = await bcrypt.compare(password, employee.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    return res.json({ success: true, user: rowToUser(employee) });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Login failed" });
  }
});

/**
 * @swagger
 * /auth/me:
 *   get:
 *     summary: Look up an employee profile by email (used to refresh user state on app start)
 *     tags: [Auth]
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: Employee profile }
 *       400: { description: Email required }
 *       404: { description: Not found }
 */
router.get("/me", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    const { rows } = await pool.query(
      `SELECT * FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [email]
    );
    if (!rows.length) return res.status(404).json({ error: "Not found" });
    return res.json({ user: rowToUser(rows[0]) });
  } catch (err) {
    console.error("/auth/me error:", err);
    return res.status(500).json({ error: "Lookup failed" });
  }
});

module.exports = router;
