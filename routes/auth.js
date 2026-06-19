const express = require("express");
const bcrypt = require("bcryptjs");
const pool = require("../dbClient");
const { safeNotify } = require("../notifier");
const {
  createResetToken,
  buildResetUrl,
  peekResetToken,
  consumeResetToken,
  RESET_TTL_HOURS,
} = require("../utils/passwordTokens");

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

/**
 * @swagger
 * /auth/forgot-password:
 *   post:
 *     summary: Request a password-reset link (emailed if the account exists)
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email]
 *             properties:
 *               email: { type: string }
 *     responses:
 *       200: { description: Always OK — does not reveal whether the email exists }
 */
router.post("/forgot-password", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    const { rows } = await pool.query(
      `SELECT email, name FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [email],
    );
    // Always answer 200 with the same body — don't leak which emails exist.
    if (rows.length) {
      const user = rows[0];
      const token = await createResetToken(user.email, RESET_TTL_HOURS);
      safeNotify("account.reset", {
        recipient: user.email,
        name: user.name || user.email,
        intro:
          "We received a request to reset your ExpGenie password. Click the button below to choose a new one. This link expires in a couple of hours.",
        ctaLabel: "Reset password",
        actionUrl: buildResetUrl(token),
      });
    }
    return res.json({ ok: true });
  } catch (err) {
    console.error("POST /auth/forgot-password error:", err);
    return res.status(500).json({ error: "Could not process request" });
  }
});

/**
 * @swagger
 * /auth/reset-password/{token}:
 *   get:
 *     summary: Check whether a reset/invite token is still valid
 *     tags: [Auth]
 *     parameters:
 *       - in: path
 *         name: token
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: "{ valid, email }" }
 *       400: { description: Invalid or expired token }
 */
router.get("/reset-password/:token", async (req, res) => {
  try {
    const email = await peekResetToken(req.params.token);
    if (!email) {
      return res.status(400).json({ valid: false, error: "This link is invalid or has expired" });
    }
    return res.json({ valid: true, email });
  } catch (err) {
    console.error("GET /auth/reset-password/:token error:", err);
    return res.status(500).json({ valid: false, error: "Could not validate link" });
  }
});

/**
 * @swagger
 * /auth/reset-password:
 *   post:
 *     summary: Set a new password using a valid reset/invite token
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [token, password]
 *             properties:
 *               token:    { type: string }
 *               password: { type: string }
 *     responses:
 *       200: { description: Password set }
 *       400: { description: Invalid input or expired token }
 */
router.post("/reset-password", async (req, res) => {
  const token = String(req.body?.token || "");
  const password = String(req.body?.password || "");
  if (!token) return res.status(400).json({ error: "Token is required" });
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }

  try {
    const email = await consumeResetToken(token);
    if (!email) {
      return res.status(400).json({ error: "This link is invalid or has expired" });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query(
      `UPDATE employees SET password_hash = $1, updated_at = NOW() WHERE LOWER(email) = LOWER($2)`,
      [passwordHash, email],
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error("POST /auth/reset-password error:", err);
    return res.status(500).json({ error: "Could not reset password" });
  }
});

module.exports = router;
