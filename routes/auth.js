const express = require("express");
const bcrypt = require("bcryptjs");
const { createRemoteJWKSet, jwtVerify } = require("jose");
const pool = require("../dbClient");
const { safeNotify } = require("../notifier");
const { createLimiter } = require("../utils/rateLimit");
const {
  issueToken,
  isTenantBlocked,
  SUSPENDED_MESSAGE,
  canActFor,
  deny,
  normEmail,
} = require("../middleware/auth");
const {
  createResetToken,
  buildResetUrl,
  peekResetToken,
  consumeResetToken,
  RESET_TTL_HOURS,
} = require("../utils/passwordTokens");

const router = express.Router();

// 10 password attempts per email per 15 minutes; 5 reset emails per email per hour.
const loginAttempts = createLimiter({ windowMs: 15 * 60 * 1000, max: 10 });
const resetRequests = createLimiter({ windowMs: 60 * 60 * 1000, max: 5 });

const BAD_CREDENTIALS = "Invalid email or password";

async function signedIn(res, employee) {
  if (employee.deactivated_at) {
    return res.status(403).json({ error: "Your ExpGenie account has been switched off." });
  }
  if (await isTenantBlocked(employee)) {
    return res.status(403).json({ error: SUSPENDED_MESSAGE });
  }
  const { token, expiresAt } = await issueToken(employee);
  return res.json({ success: true, user: rowToUser(employee), token, expiresAt });
}

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
    avatarUrl: row.avatar_url || null,
    integrationProvider: row.integration_provider || null,
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
 *       200: { description: "{ success, user, token, expiresAt } — send token as Authorization: Bearer" }
 *       400: { description: Missing fields }
 *       401: { description: Invalid email or password }
 *       403: { description: Workspace suspended }
 *       429: { description: Too many attempts }
 *       500: { description: Login failed }
 */
router.post("/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const wait = loginAttempts(normEmail(email));
  if (wait) {
    res.set("Retry-After", String(wait));
    return res.status(429).json({ error: "Too many sign-in attempts. Try again in a few minutes." });
  }

  try {
    const { rows } = await pool.query(
      `SELECT * FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [email]
    );

    // One answer for "no such user", "no password yet" and "wrong password", so
    // the sign-in form can't be used to find out who has an account.
    const employee = rows[0];
    if (!employee?.password_hash) {
      return res.status(401).json({ error: BAD_CREDENTIALS });
    }

    const ok = await bcrypt.compare(password, employee.password_hash);
    if (!ok) {
      return res.status(401).json({ error: BAD_CREDENTIALS });
    }

    return await signedIn(res, employee);
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Login failed" });
  }
});

/**
 * @swagger
 * /auth/me:
 *   get:
 *     summary: The signed-in employee's profile (used to refresh user state on app start)
 *     description: Without email, returns the caller. With it, the caller must be that person, their tenant admin or a super-admin.
 *     tags: [Auth]
 *     parameters:
 *       - in: query
 *         name: email
 *         required: false
 *         schema: { type: string }
 *     responses:
 *       200: { description: Employee profile }
 *       400: { description: Email required }
 *       404: { description: Not found }
 */
router.get("/me", async (req, res) => {
  const email = req.query.email || req.auth?.email;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    if (!(await canActFor(req, email))) return deny(res);
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
  // Over the limit: answer as usual, just don't send another email.
  if (resetRequests(email)) return res.json({ ok: true });

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
    // Sessions signed in before the reset stop working (see middleware/auth.js).
    await pool.query(
      `UPDATE employees
          SET password_hash = $1, auth_valid_after = date_trunc('second', NOW()), updated_at = NOW()
        WHERE LOWER(email) = LOWER($2)`,
      [passwordHash, email],
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error("POST /auth/reset-password error:", err);
    return res.status(500).json({ error: "Could not reset password" });
  }
});

// ── Microsoft sign-in (mobile) ───────────────────────────────────────────────
//
// The mobile app signs in with Microsoft on its own and gets an ID token. It
// posts that here; we check Microsoft's signature, that the token was issued to
// our app (audience) by an allowed Azure AD tenant (issuer), and hand back our
// own session token for the employee with that email.
//
//   MICROSOFT_CLIENT_IDS  comma-separated Azure app (client) IDs we accept as audience
//   MICROSOFT_TENANT_IDS  comma-separated Azure AD tenant IDs allowed to sign in

const MS_JWKS = createRemoteJWKSet(
  new URL("https://login.microsoftonline.com/common/discovery/v2.0/keys"),
);

function csvEnv(name) {
  return String(process.env[name] || "")
    .split(",")
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * @swagger
 * /auth/microsoft:
 *   post:
 *     summary: Exchange a Microsoft ID token for an ExpGenie session token
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [idToken]
 *             properties:
 *               idToken: { type: string }
 *     responses:
 *       200: { description: "{ success, user, token, expiresAt }" }
 *       401: { description: Token not valid }
 *       403: { description: No ExpGenie account for this Microsoft user, or workspace suspended }
 *       503: { description: Microsoft sign-in not configured on the server }
 */
router.post("/microsoft", async (req, res) => {
  const idToken = String(req.body?.idToken || "");
  if (!idToken) return res.status(400).json({ error: "idToken is required" });

  const clientIds = csvEnv("MICROSOFT_CLIENT_IDS");
  const tenantIds = csvEnv("MICROSOFT_TENANT_IDS");
  if (!clientIds.length || !tenantIds.length) {
    return res.status(503).json({ error: "Microsoft sign-in is not configured on the server." });
  }

  let claims;
  try {
    ({ payload: claims } = await jwtVerify(idToken, MS_JWKS, {
      audience: clientIds,
      algorithms: ["RS256"],
    }));
  } catch (err) {
    console.warn("POST /auth/microsoft rejected token:", err.code || err.message);
    return res.status(401).json({ error: "Microsoft sign-in could not be verified. Try again." });
  }

  const tid = String(claims.tid || "").toLowerCase();
  if (!tenantIds.includes(tid) || claims.iss !== `https://login.microsoftonline.com/${claims.tid}/v2.0`) {
    return res.status(403).json({ error: "This Microsoft organisation is not allowed to sign in." });
  }

  const email = normEmail(claims.email || claims.preferred_username || claims.upn);
  if (!email) return res.status(401).json({ error: "Microsoft did not share an email address." });

  try {
    const { rows } = await pool.query(
      `SELECT * FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [email],
    );
    if (!rows.length) {
      return res.status(403).json({
        error: "Your Microsoft account isn't set up in ExpGenie yet. Ask your admin to add you.",
      });
    }
    return await signedIn(res, rows[0]);
  } catch (err) {
    console.error("POST /auth/microsoft error:", err);
    return res.status(500).json({ error: "Sign-in failed" });
  }
});

module.exports = router;
module.exports.rowToUser = rowToUser;
module.exports.signedIn = signedIn;
