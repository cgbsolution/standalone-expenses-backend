// Who is calling, and may they do this?
//
// Sign-in (POST /auth/login, POST /auth/microsoft) issues a signed token. Every
// other request carries it as `Authorization: Bearer <token>`. `authenticate`
// verifies it, re-reads the employee row — so a deleted user, a changed role or
// a suspended tenant takes effect at once, not when the token expires — and
// puts the caller on `req.auth = { email, name, role, tenant }`.
//
// Routes never trust an email, tenant slug or role sent in the request. They
// ask the helpers at the bottom of this file whether the caller may act on it.
//
// AUTH_ENFORCEMENT=report is a rollout switch for mobile builds that don't send
// the token yet: a request WITHOUT a token is let through with `req.auth = null`
// and logged, and the helpers allow it as before. A request WITH a token is
// always checked in full. The default is "on" — no token, no access.

const crypto = require("crypto");
const { SignJWT, jwtVerify, decodeJwt } = require("jose");
const pool = require("../dbClient");

const ISSUER = "expgenie";
const AUDIENCE = "expgenie-api";
const TOKEN_TTL = process.env.AUTH_TOKEN_TTL || "7d";
const ENFORCEMENT =
  String(process.env.AUTH_ENFORCEMENT || "on").trim().toLowerCase() === "report" ? "report" : "on";

let secret = process.env.AUTH_JWT_SECRET || "";
if (!secret) {
  console.warn(
    "[auth] AUTH_JWT_SECRET is not set — using a random one. Sessions will not survive a restart " +
      "and the dashboard cannot verify them. Set the same AUTH_JWT_SECRET on the backend and the dashboard.",
  );
  secret = crypto.randomBytes(48).toString("hex");
} else if (secret.length < 32) {
  console.warn("[auth] AUTH_JWT_SECRET is shorter than 32 characters. Use a long random value.");
}
const KEY = new TextEncoder().encode(secret);

if (ENFORCEMENT === "report") {
  console.warn(
    "[auth] AUTH_ENFORCEMENT=report — requests without a token are still accepted. " +
      "Switch to 'on' once every mobile install sends the token.",
  );
}

// A suspended or churned tenant's people can't sign in or use the API.
const BLOCKED_TENANT_STATUSES = new Set(["suspended", "churned"]);
const SUSPENDED_MESSAGE = "This workspace has been suspended. Contact ExpGenie support.";

// Method + path pairs reachable without a token.
const PUBLIC_ROUTES = [
  ["GET", /^\/$/],
  ["GET", /^\/api-docs(\/.*)?$/],
  ["POST", /^\/auth\/login\/?$/],
  ["POST", /^\/auth\/microsoft\/?$/],
  ["POST", /^\/auth\/forgot-password\/?$/],
  ["GET", /^\/auth\/reset-password\/[^/]+\/?$/],
  ["POST", /^\/auth\/reset-password\/?$/],
  // AskMira server-to-server calls carry their own signed assertion, checked in the route.
  ["POST", /^\/integrations\/askmira\/.+$/],
  ["POST", /^\/auth\/askmira\/exchange\/?$/],
];

function isPublic(req) {
  return PUBLIC_ROUTES.some(([method, pattern]) => req.method === method && pattern.test(req.path));
}

function normEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function sameEmail(a, b) {
  const left = normEmail(a);
  return Boolean(left) && left === normEmail(b);
}

/** The caller as the database knows them now, or null if they no longer exist. */
async function loadCaller(email) {
  const { rows } = await pool.query(
    `SELECT e.email, e.name, e.role, e.tenant, e.auth_valid_after, e.deactivated_at,
            ts.status AS tenant_status
       FROM employees e
       LEFT JOIN tenant_settings ts ON ts.slug = e.tenant
      WHERE LOWER(e.email) = LOWER($1)
      LIMIT 1`,
    [email],
  );
  const row = rows[0];
  // Switched off (by AskMira, for a leaver): as good as gone.
  if (!row || row.deactivated_at) return null;
  const role = String(row.role || "employee").toLowerCase();
  const isSuper = role === "super_admin";
  return {
    email: normEmail(row.email),
    name: row.name || "",
    role,
    tenant: isSuper ? null : row.tenant || null,
    validAfter: row.auth_valid_after ? new Date(row.auth_valid_after).getTime() : 0,
    suspended: !isSuper && BLOCKED_TENANT_STATUSES.has(String(row.tenant_status || "").toLowerCase()),
  };
}

/** Is this employee's tenant blocked? Used at sign-in, before a token exists. */
async function isTenantBlocked(employeeRow) {
  const role = String(employeeRow?.role || "").toLowerCase();
  if (!employeeRow?.tenant || role === "super_admin") return false;
  const { rows } = await pool.query(`SELECT status FROM tenant_settings WHERE slug = $1`, [
    employeeRow.tenant,
  ]);
  return BLOCKED_TENANT_STATUSES.has(String(rows[0]?.status || "").toLowerCase());
}

/** Mint a session token for an employee row. */
async function issueToken(employeeRow) {
  const role = String(employeeRow.role || "employee").toLowerCase();
  const tenant = role === "super_admin" ? null : employeeRow.tenant || null;
  const token = await new SignJWT({ role, tenant, tenantSlug: tenant, name: employeeRow.name || "" })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(normEmail(employeeRow.email))
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(TOKEN_TTL)
    .setJti(crypto.randomUUID())
    .sign(KEY);
  return { token, expiresAt: decodeJwt(token).exp * 1000 };
}

const reported = new Set();
function noteUnauthenticated(req) {
  const key = `${req.method} ${req.baseUrl || ""}${req.path}`;
  if (reported.has(key) || reported.size > 500) return;
  reported.add(key);
  console.warn(`[auth] report mode: ${key} called without a token`);
}

async function authenticate(req, res, next) {
  if (req.method === "OPTIONS" || isPublic(req)) return next();

  const match = /^Bearer\s+(.+)$/i.exec(req.get("authorization") || "");
  if (!match) {
    if (ENFORCEMENT === "report") {
      noteUnauthenticated(req);
      req.auth = null;
      return next();
    }
    return res.status(401).json({ error: "Please sign in." });
  }

  try {
    const { payload } = await jwtVerify(match[1].trim(), KEY, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ["HS256"],
    });
    const caller = await loadCaller(payload.sub);
    if (!caller) {
      return res.status(401).json({ error: "Your account no longer exists. Please sign in again." });
    }
    // Tokens issued before a password reset stop working.
    if (caller.validAfter && (payload.iat || 0) * 1000 < caller.validAfter) {
      return res.status(401).json({ error: "Your session has ended. Please sign in again." });
    }
    if (caller.suspended) return res.status(403).json({ error: SUSPENDED_MESSAGE });
    delete caller.validAfter;
    delete caller.suspended;
    req.auth = caller;
    return next();
  } catch (err) {
    if (String(err?.code || "").startsWith("ERR_JW")) {
      return res.status(401).json({ error: "Your session has expired. Please sign in again." });
    }
    return next(err);
  }
}

// ── Authorisation helpers ────────────────────────────────────────────────────
//
// Each returns true when the caller may proceed. `req.auth === null` only ever
// happens in report mode for a request without a token: those keep the old,
// trust-the-client behaviour until enforcement is switched on.

function isLegacy(req) {
  return req.auth === null && ENFORCEMENT === "report";
}

function isSuper(req) {
  return req.auth?.role === "super_admin";
}

function requireSuper(req) {
  if (isLegacy(req)) return true;
  return isSuper(req);
}

async function employeeByEmail(email) {
  if (!email) return null;
  const { rows } = await pool.query(
    `SELECT email, role, tenant FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
    [email],
  );
  return rows[0] || null;
}

/** Self, an admin of that person's tenant, or a super-admin. */
async function canActFor(req, email) {
  if (isLegacy(req)) return true;
  if (!req.auth || !email) return false;
  if (sameEmail(req.auth.email, email) || isSuper(req)) return true;
  if (req.auth.role !== "admin") return false;
  const target = await employeeByEmail(email);
  return Boolean(target && target.role !== "super_admin" && target.tenant === req.auth.tenant);
}

/** An admin of tenant `slug`, or a super-admin. */
function canAdminTenant(req, slug) {
  if (isLegacy(req)) return true;
  if (!req.auth) return false;
  if (isSuper(req)) return true;
  return req.auth.role === "admin" && Boolean(slug) && req.auth.tenant === slug;
}

/** Anyone in tenant `slug`, or a super-admin. */
function canReadTenant(req, slug) {
  if (isLegacy(req)) return true;
  if (!req.auth) return false;
  if (isSuper(req)) return true;
  return Boolean(slug) && req.auth.tenant === slug;
}

// Expenses carry no tenant column; it is the submitter's (or, failing that,
// the approver's) tenant.
async function expenseTenant(row) {
  for (const email of [row.submitter_email, row.approver_email].filter(Boolean)) {
    const employee = await employeeByEmail(email);
    if (employee?.tenant) return employee.tenant;
  }
  return "";
}

/** The submitter, anyone who has been its approver, an admin of its tenant, or a super-admin. */
async function canViewExpense(req, row) {
  if (isLegacy(req)) return true;
  if (!req.auth) return false;
  if (isSuper(req)) return true;
  const me = req.auth.email;
  if (sameEmail(me, row.submitter_email) || sameEmail(me, row.approver_email)) return true;
  const history = Array.isArray(row.data?.ApprovalHistory) ? row.data.ApprovalHistory : [];
  if (history.some((entry) => sameEmail(entry?.by, me))) return true;
  return req.auth.role === "admin" && (await expenseTenant(row)) === req.auth.tenant;
}

/** Approve or reject: the current approver, or an admin of its tenant. */
async function canDecideExpense(req, row) {
  if (isLegacy(req)) return true;
  if (!req.auth) return false;
  if (sameEmail(req.auth.email, row.approver_email)) return true;
  return req.auth.role === "admin" && (await expenseTenant(row)) === req.auth.tenant;
}

/** The email to record as the actor: the caller, or (report mode only) what the client sent. */
function actorEmail(req, claimed) {
  return req.auth?.email || claimed || "";
}

function deny(res, message = "You don't have access to that.") {
  return res.status(403).json({ error: message });
}

module.exports = {
  authenticate,
  issueToken,
  isTenantBlocked,
  SUSPENDED_MESSAGE,
  ENFORCEMENT,
  // helpers
  isLegacy,
  isSuper,
  requireSuper,
  canActFor,
  canAdminTenant,
  canReadTenant,
  canViewExpense,
  canDecideExpense,
  expenseTenant,
  employeeByEmail,
  actorEmail,
  sameEmail,
  normEmail,
  deny,
};
