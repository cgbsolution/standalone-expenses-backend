// Password set/reset tokens. Backs both the "set your password" invite emails
// (new tenant admins + invited employees) and the self-service forgot-password
// flow. One table, one token type — the only difference is the email copy.

const crypto = require("crypto");
const pool = require("../dbClient");

// Where the dashboard lives — used to build the link embedded in emails.
// MUST be set to the deployed dashboard origin in production.
const APP_BASE_URL = (process.env.APP_BASE_URL || "http://localhost:3000").replace(/\/$/, "");

// Invite links (new accounts) last longer than self-service resets.
const INVITE_TTL_HOURS = 72;
const RESET_TTL_HOURS = 2;

async function ensurePasswordResetTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      token       TEXT PRIMARY KEY,
      email       TEXT NOT NULL,
      expires_at  TIMESTAMPTZ NOT NULL,
      used_at     TIMESTAMPTZ,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function createResetToken(email, ttlHours) {
  const token = crypto.randomBytes(32).toString("hex");
  await pool.query(
    `INSERT INTO password_resets (token, email, expires_at)
     VALUES ($1, LOWER($2), NOW() + make_interval(hours => $3::int))`,
    [token, email, ttlHours],
  );
  return token;
}

function buildResetUrl(token) {
  return `${APP_BASE_URL}/reset-password?token=${token}`;
}

// Returns the email if the token is valid, unused and unexpired — else null.
// Read-only; used by the GET validation endpoint before showing the form.
async function peekResetToken(token) {
  if (!token) return null;
  const { rows } = await pool.query(
    `SELECT email FROM password_resets
      WHERE token = $1 AND used_at IS NULL AND expires_at > NOW()
      LIMIT 1`,
    [token],
  );
  return rows.length ? rows[0].email : null;
}

// Atomically marks the token used and returns its email, or null if invalid.
async function consumeResetToken(token) {
  if (!token) return null;
  const { rows } = await pool.query(
    `UPDATE password_resets
        SET used_at = NOW()
      WHERE token = $1 AND used_at IS NULL AND expires_at > NOW()
      RETURNING email`,
    [token],
  );
  return rows.length ? rows[0].email : null;
}

module.exports = {
  APP_BASE_URL,
  INVITE_TTL_HOURS,
  RESET_TTL_HOURS,
  ensurePasswordResetTable,
  createResetToken,
  buildResetUrl,
  peekResetToken,
  consumeResetToken,
};
