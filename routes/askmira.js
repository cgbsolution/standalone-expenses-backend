// The link with AskMira, the HRMS a company may already run its people in.
//
// AskMira is the source of truth for a linked company and its people. It calls
// here server to server to create (or adopt) the tenant and to send who should
// have access, and it sends people here already signed in with a one-time link.
//
// Each AskMira workspace connects to one tenant here, started by its admin in
// AskMira and allowed by an admin of the tenant here ("Connecting" below); the
// connection has its own secret, which reaches that tenant only. Every request
// carries a short-lived HS256 token signed with that secret (aud
// "askmira:expense", iss "askmira"), or, for a workspace linked the older way,
// with ASKMIRA_SHARED_SECRET:
//
//   POST /integrations/askmira/organizations   use=provision, `bh` = SHA-256 of the body
//   POST /integrations/askmira/users/sync      use=provision, `bh` = SHA-256 of the body
//   POST /integrations/askmira/query           use=query, `bh` = SHA-256 of the body
//   POST /integrations/askmira/connect/token   AskMira's server swaps a one-time code (PKCE)
//   POST /integrations/askmira/connect/revoke  use=revoke, `bh`; AskMira disconnected
//   POST /auth/askmira/exchange                use=launch; each `jti` is accepted once
//
// `query` is read-only: AskMira's companion asks it on behalf of one person
// (see "Read-only queries" below).
//
// Employees AskMira manages carry `askmira_user_id`. Only they are switched off
// (`deactivated_at`) when they drop out of AskMira's roster; people added here
// directly are never touched.

const crypto = require("crypto");
const express = require("express");
const { decodeJwt, jwtVerify } = require("jose");
const pool = require("../dbClient");
const { signedIn } = require("./auth");
const { normEmail, SUSPENDED_MESSAGE } = require("../middleware/auth");

// As for a signed-in dashboard request (middleware/auth.js loadCaller).
const BLOCKED_TENANT_STATUSES = new Set(["suspended", "churned"]);

async function refuseBlocked(slug) {
  const { rows } = await pool.query(`SELECT status FROM tenant_settings WHERE slug = $1`, [slug]);
  if (BLOCKED_TENANT_STATUSES.has(String(rows[0]?.status || "").toLowerCase())) {
    throw httpError(403, SUSPENDED_MESSAGE);
  }
}

const AUDIENCE = "askmira:expense";
const ISSUER = "askmira";
const ROLES = new Set(["admin", "employee"]);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const integrationRouter = express.Router();
const authRouter = express.Router();
const connectionRouter = express.Router();

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

// ── Token checks ─────────────────────────────────────────────────────────────
//
// A token is checked with the secret of the workspace it names — `sub` on
// server-to-server calls, `tid` on a sign-in link — so one workspace's secret
// can never act for another. A workspace that has not connected from AskMira's
// Connectors falls back to ASKMIRA_SHARED_SECRET; with neither, the endpoints
// behave as if they did not exist.

function serverKey() {
  return process.env.AUTH_JWT_SECRET || "";
}

// A tenant's AskMira secret: derived, so the database holds only the nonce.
function derive(slug, nonce) {
  return crypto.createHmac("sha256", serverKey()).update(`askmira-org:v1:${slug}:${nonce}`).digest("hex");
}

async function tenantSecret(tenantId) {
  if (!tenantId) return null;
  try {
    const { rows } = await pool.query(
      `SELECT slug, secret_nonce FROM askmira_links WHERE askmira_tenant_id = $1 AND secret_nonce IS NOT NULL`,
      [tenantId],
    );
    return rows[0] ? derive(rows[0].slug, rows[0].secret_nonce) : null;
  } catch {
    return null; // before the columns exist: no connections made here
  }
}

async function secretKey(tenantId) {
  const secret = (await tenantSecret(tenantId)) || process.env.ASKMIRA_SHARED_SECRET || "";
  // Off (or misconfigured): behave as if the endpoints did not exist.
  if (secret.length < 32) throw httpError(404, "Route not found");
  return new TextEncoder().encode(secret);
}

async function claimsOf(token, use) {
  let unverified;
  try {
    unverified = decodeJwt(token);
  } catch {
    await secretKey(""); // names no workspace: as if absent unless the older link is on
    throw httpError(401, "This AskMira link is not valid or has expired.");
  }
  // Whose secret to check with: the workspace the token is for.
  const key = await secretKey(String((use === "launch" ? unverified.tid : unverified.sub) || ""));
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
async function provisionClaims(req, use = "provision") {
  const match = /^Bearer\s+(.+)$/i.exec(req.get("authorization") || "");
  if (!match) {
    await secretKey(String(req.body?.tenant_id || "")); // as if absent where the link is off
    throw httpError(401, "Missing AskMira assertion.");
  }
  const claims = await claimsOf(match[1].trim(), use);
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

// ── Read-only queries for AskMira's companion ────────────────────────────────
//
// Ask Mira, AskMira's AI companion, asks on behalf of one person and shows the
// answer to that person only; no model reads it.
//
//   POST /integrations/askmira/query   use=query, `bh` = SHA-256 of the body
//   { tenant_id, actor: { id, email, role }, kind: "claims" | "summary", params }
//
// An answer covers only expenses submitted by employees of the tenant linked to
// the workspace in the token. The person must be an active employee of that
// tenant here, and sees what they see when they open ExpGenie:
//
//   scope "mine"       their own claims
//   scope "approvals"  claims now waiting on them as approver
//   scope "company"    everyone's: only for an admin here whom AskMira also calls admin
//
// Amounts are added up in Postgres as numeric and returned as strings, never as
// floats. A claim's amount is read the way the dashboard reads it
// (lib/expense.ts expenseTotal): TotalAmount with commas and symbols ignored,
// or the sum of its invoice lines when that is missing or not positive.

const SCOPES = new Set(["mine", "approvals", "company"]);
const CLAIM_STATUSES = new Map(
  ["Pending", "Approved", "Rejected", "Draft"].map((status) => [status.toLowerCase(), status]),
);
// A year (and a day, for a leap year): AskMira asks about "the last 12 months".
const MAX_WINDOW_MS = 366 * 24 * 60 * 60 * 1000;

// A text expression as numeric, or NULL when it holds no number. Only ever
// given SQL written in this file, never input.
function amountOf(expr) {
  const digits = `regexp_replace(COALESCE(${expr}, ''), '[^0-9.-]', '', 'g')`;
  return `(CASE WHEN ${digits} ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN ${digits}::numeric END)`;
}

// Every claim of the tenant ($1), one row each, in the shape the answers use.
// The status is read as the clients read it: anything starting "approv" is
// Approved (the chatbot writes variants such as "ApprovedByFinance").
const CLAIMS = `
  SELECT e.id, e.unique_key, e.submitter_email, e.approver_email, e.created_at,
         COALESCE(NULLIF(TRIM(e.submitter_name), ''), s.name) AS submitter,
         COALESCE(NULLIF(TRIM(e.data->>'ExpenseTitle'), ''), 'Untitled claim') AS title,
         CASE WHEN e.approval_status ~* '^approv' THEN 'Approved'
              WHEN e.approval_status ~* '^reject' THEN 'Rejected'
              WHEN e.approval_status ~* '^draft' THEN 'Draft'
              ELSE 'Pending' END AS status,
         CASE WHEN e.data->>'PaymentStatus' = 'Paid' THEN 'Paid' ELSE 'Unpaid' END AS payment,
         ROUND(CASE WHEN ${amountOf("e.data->>'TotalAmount'")} > 0
                    THEN ${amountOf("e.data->>'TotalAmount'")}
                    ELSE COALESCE(line_totals.total, 0) END, 2) AS amount,
         COALESCE(NULLIF(TRIM(arr.lines->0->>'Currency'), ''),
                  NULLIF(TRIM(e.data->>'Currency'), ''), 'INR') AS currency,
         COALESCE(NULLIF(TRIM(arr.lines->0->>'Category'), ''),
                  NULLIF(TRIM(arr.lines->0->>'ExpenseType'), ''),
                  NULLIF(TRIM(arr.lines->0->>'SubCategory'), ''), 'Uncategorised') AS category
    FROM expenses e
    JOIN employees s ON LOWER(s.email) = LOWER(e.submitter_email) AND s.tenant = $1
    CROSS JOIN LATERAL (
      SELECT CASE WHEN jsonb_typeof(e.data->'ExpenseData') = 'array'
                  THEN e.data->'ExpenseData' ELSE '[]'::jsonb END AS lines
    ) arr
    LEFT JOIN LATERAL (
      SELECT SUM(${amountOf("item->>'InvoiceAmount'")}) AS total
        FROM jsonb_array_elements(arr.lines) AS item
    ) line_totals ON TRUE
`;

function instantOf(value, name) {
  if (value == null || value === "") return null;
  const moment = new Date(String(value));
  if (Number.isNaN(moment.getTime())) throw httpError(422, `${name} must be an ISO 8601 time.`);
  return moment;
}

// The WHERE clause for one question, with its values from $2 on ($1 is the tenant).
function filtersFor(scope, actorEmail, params) {
  const values = [];
  const where = [];
  const bind = (value) => {
    values.push(value);
    return `$${values.length + 1}`;
  };
  if (scope === "mine") where.push(`LOWER(c.submitter_email) = LOWER(${bind(actorEmail)})`);
  if (scope === "approvals") where.push(`LOWER(c.approver_email) = LOWER(${bind(actorEmail)})`);

  const status = CLAIM_STATUSES.get(String(params.status || "").toLowerCase());
  if (status) where.push(`c.status = ${bind(status)}`);

  const from = instantOf(params.from, "from");
  const to = instantOf(params.to, "to");
  if (from && to && (to <= from || to - from > MAX_WINDOW_MS)) {
    throw httpError(422, "The window must end after it starts, within a year.");
  }
  if (from) where.push(`c.created_at >= ${bind(from.toISOString())}::timestamptz`);
  if (to) where.push(`c.created_at < ${bind(to.toISOString())}::timestamptz`);

  const text = String(params.query || "").trim().slice(0, 100);
  // "Meera auto": each word matches some field (a person and a title word), not the phrase.
  for (const word of text.split(/\s+/).filter(Boolean).slice(0, 6)) {
    // ILIKE's own wildcards are taken literally.
    const pattern = bind(`%${word.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`);
    where.push(`(c.title ILIKE ${pattern} OR c.category ILIKE ${pattern} OR c.submitter ILIKE ${pattern})`);
  }
  return { where, values };
}

function limitOf(params) {
  const n = Number.parseInt(params.limit, 10);
  return Number.isFinite(n) ? Math.min(Math.max(n, 1), 50) : 25;
}

async function claimsAnswer(slug, actorEmail, scope, params) {
  const { where, values } = filtersFor(scope, actorEmail, params);
  const from = `FROM (${CLAIMS}) c ${where.length ? `WHERE ${where.join(" AND ")}` : ""}`;
  const args = [slug, ...values];
  const { rows: [{ total }] } = await pool.query(`SELECT COUNT(*)::int AS total ${from}`, args);
  const { rows } = await pool.query(
    `SELECT c.id, c.unique_key, c.title, c.submitter, c.status, c.payment, c.amount::text AS amount,
            c.currency, c.category, c.created_at
       ${from}
      ORDER BY c.created_at DESC, c.id DESC
      LIMIT ${limitOf(params)}`,
    args,
  );
  return {
    total,
    claims: rows.map((row) => ({
      id: String(row.id),
      reference: row.unique_key,
      title: row.title,
      submitter: row.submitter,
      status: row.status,
      payment: row.payment,
      amount: row.amount,
      currency: row.currency,
      category: row.category,
      submitted_at: new Date(row.created_at).toISOString(),
    })),
  };
}

async function summaryAnswer(slug, actorEmail, scope, params) {
  const { where, values } = filtersFor(scope, actorEmail, params);
  const from = `FROM (${CLAIMS}) c ${where.length ? `WHERE ${where.join(" AND ")}` : ""}`;
  const unpaidFrom = `FROM (${CLAIMS}) c WHERE ${[...where, "c.status = 'Approved'", "c.payment = 'Unpaid'"].join(" AND ")}`;
  const args = [slug, ...values];
  const [byStatus, byCategory, unpaid, bySubmitter, byMonth] = await Promise.all([
    pool.query(
      `SELECT c.status, c.currency, COUNT(*)::int AS count, SUM(c.amount)::text AS amount
         ${from} GROUP BY c.status, c.currency ORDER BY c.status, c.currency`,
      args,
    ),
    pool.query(
      `SELECT c.category, c.currency, COUNT(*)::int AS count, SUM(c.amount)::text AS amount
         ${from} GROUP BY c.category, c.currency ORDER BY SUM(c.amount) DESC, c.category LIMIT 10`,
      args,
    ),
    pool.query(
      `SELECT c.currency, COUNT(*)::int AS count, SUM(c.amount)::text AS amount
         ${unpaidFrom} GROUP BY c.currency ORDER BY c.currency`,
      args,
    ),
    // Who submitted how much. Only within the same scope as everything above:
    // for "mine" that is the asker alone.
    pool.query(
      `SELECT c.submitter, LOWER(c.submitter_email) AS email, c.currency, COUNT(*)::int AS count,
              SUM(c.amount)::text AS amount
         ${from} GROUP BY c.submitter, LOWER(c.submitter_email), c.currency
         ORDER BY SUM(c.amount) DESC, c.submitter LIMIT 500`,
      args,
    ),
    // Month by month in India's time (a fixed +05:30: India keeps no daylight
    // saving, and not every Postgres ships the zone names), with how many people.
    pool.query(
      `SELECT to_char(c.created_at AT TIME ZONE INTERVAL '+05:30', 'YYYY-MM') AS month, c.currency,
              COUNT(*)::int AS count, COUNT(DISTINCT LOWER(c.submitter_email))::int AS people,
              SUM(c.amount)::text AS amount
         ${from} GROUP BY 1, c.currency ORDER BY 1, c.currency`,
      args,
    ),
  ]);
  return {
    by_status: byStatus.rows,
    by_category: byCategory.rows,
    approved_unpaid: unpaid.rows,
    by_submitter: bySubmitter.rows,
    by_month: byMonth.rows,
  };
}

// Approved claims nobody has paid yet, each with who submitted it: what AskMira's
// payroll pays with salary. Company scope only (an admin here and in AskMira).
async function payableAnswer(slug, actorEmail, scope) {
  if (scope !== "company") throw httpError(403, "Only the whole company's claims are paid by payroll.");
  const { rows } = await pool.query(
    `SELECT c.unique_key, c.title, LOWER(c.submitter_email) AS submitter_email, c.submitter,
            c.amount::text AS amount, c.currency, c.category, c.created_at
       FROM (${CLAIMS}) c
      WHERE c.status = 'Approved' AND c.payment = 'Unpaid' AND c.amount > 0
      ORDER BY c.created_at, c.id
      LIMIT 1000`,
    [slug],
  );
  return {
    claims: rows.map((row) => ({
      reference: row.unique_key,
      title: row.title,
      submitter: row.submitter,
      submitter_email: row.submitter_email,
      amount: row.amount,
      currency: row.currency,
      category: row.category,
      submitted_at: new Date(row.created_at).toISOString(),
    })),
  };
}

// The categories the person may claim under, whether each needs a bill, and the
// cap their own grade has on it: what Ask Mira checks before it offers a claim.
async function categoriesAnswer(slug, actorEmail) {
  const { rows: [me] } = await pool.query(
    `SELECT grade FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
    [actorEmail],
  );
  const grade = me && me.grade ? String(me.grade) : null;
  const { rows } = await pool.query(
    `SELECT c.name, c.requires_bill, p.cap_amount::text AS cap, p.is_actuals
       FROM expense_categories c
       LEFT JOIN tenant_policy_caps p
              ON p.slug = c.slug AND p.grade = $2
             AND LOWER(p.normalized) = LOWER(COALESCE(NULLIF(c.normalized, ''), c.name))
      WHERE c.slug = $1 AND c.enabled IS NOT FALSE
      ORDER BY c.name`,
    [slug, grade],
  );
  return {
    grade,
    categories: rows.map((r) => ({
      name: r.name,
      requires_bill: r.requires_bill !== false,
      // No cap, or "actuals" (whatever it cost): null.
      cap: r.cap && !r.is_actuals && Number(r.cap) > 0 ? r.cap : null,
    })),
  };
}

// The same bill claimed before by this person, in a claim that is not rejected:
// the same invoice number from the same vendor (or with no vendor given), or the
// same vendor, date and amount.
async function earlierClaimsOf(slug, actorEmail, lines) {
  const found = [];
  const { rows } = await pool.query(
    `SELECT e.id, e.unique_key, e.approval_status,
            COALESCE(NULLIF(TRIM(e.data->>'ExpenseTitle'), ''), 'Untitled claim') AS title,
            item->>'InvoiceNumber' AS invoice, item->>'VendorName' AS vendor,
            item->>'DocumentDate' AS day, item->>'InvoiceAmount' AS amount
       FROM expenses e
       JOIN employees s ON LOWER(s.email) = LOWER(e.submitter_email) AND s.tenant = $1
       CROSS JOIN LATERAL jsonb_array_elements(
         CASE WHEN jsonb_typeof(e.data->'ExpenseData') = 'array' THEN e.data->'ExpenseData' ELSE '[]'::jsonb END
       ) AS item
      WHERE LOWER(e.submitter_email) = LOWER($2)
        AND COALESCE(e.approval_status, '') !~* '^reject'`,
    [slug, actorEmail],
  );
  const same = (a, b) => String(a || "").trim().toLowerCase() === String(b || "").trim().toLowerCase();
  lines.forEach((line, index) => {
    const invoice = String(line.invoice_number || "").trim();
    const vendor = String(line.vendor || "").trim();
    const amount = Number(String(line.amount ?? "").replace(/[,₹\s]/g, ""));
    const hit = rows.find((row) => {
      if (invoice && same(row.invoice, invoice)) return !vendor || !row.vendor || same(row.vendor, vendor);
      return Boolean(vendor) && same(row.vendor, vendor) && same(row.day, line.date) &&
        Math.abs(Number(row.amount) - amount) < 0.005;
    });
    if (hit) {
      found.push({ line: index + 1, reference: hit.unique_key, title: hit.title, status: hit.approval_status || "Pending" });
    }
  });
  return found;
}

async function billsAnswer(slug, actorEmail, _scope, params) {
  const lines = Array.isArray(params.lines) ? params.lines.slice(0, MAX_LINES) : [];
  return { duplicates: await earlierClaimsOf(slug, actorEmail, lines) };
}

const QUERIES = {
  claims: claimsAnswer,
  summary: summaryAnswer,
  payable: payableAnswer,
  categories: categoriesAnswer,
  bills: billsAnswer,
};

integrationRouter.post(
  "/query",
  handle(async (req) => {
    await provisionClaims(req, "query");
    const kind = String(req.body.kind || "");
    const answer = Object.prototype.hasOwnProperty.call(QUERIES, kind) ? QUERIES[kind] : null;
    if (!answer) throw httpError(422, "Unknown query.");
    const slug = await linkedSlug(String(req.body.tenant_id));
    if (!slug) throw httpError(404, "This workspace is not linked here yet.");
    await refuseBlocked(slug);

    const actor = req.body.actor && typeof req.body.actor === "object" ? req.body.actor : {};
    const email = normEmail(actor.email);
    const role = String(actor.role || "");
    const { rows } = await pool.query(
      `SELECT email, role, tenant, deactivated_at FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [email],
    );
    const me = rows[0];
    if (!EMAIL_RE.test(email) || !ROLES.has(role) || !me || me.tenant !== slug || me.deactivated_at || me.role === "super_admin") {
      throw httpError(403, "You don't have an ExpGenie account in this workspace yet. Open ExpGenie once from AskMira, then ask again.");
    }

    const params = req.body.params && typeof req.body.params === "object" ? req.body.params : {};
    const scope = String(params.scope || "mine");
    if (!SCOPES.has(scope)) throw httpError(422, "Unknown scope.");
    if (scope === "company" && !(me.role === "admin" && role === "admin")) {
      throw httpError(403, "Only an ExpGenie admin sees the whole company's expenses.");
    }
    const result = await answer(slug, me.email, scope, params);
    console.log(`[AskMira] query ${kind}/${scope} for ${slug} by ${email}`);
    return { kind, scope, ...result };
  }),
);

// ── Actions for AskMira ──────────────────────────────────────────────────────
//
//   POST /integrations/askmira/act   use=act, `bh` = SHA-256 of the body, each `jti` once
//   { tenant_id, actor: { id, email, role }, kind: "claims.paid", params }
//
//   claims.paid   AskMira's payroll paid these approved claims with salary.
//                 params: { references: [...], paid_on: "YYYY-MM-DD", note }
//                 Each one of this tenant's, approved and still unpaid, is
//                 marked Paid (Method "AskMira payroll") with a history entry;
//                 anything else is skipped and says why. Asking again changes
//                 nothing: a claim already paid is reported as such.
//
//   claim.create  The person files their own claim, from what Ask Mira read off a
//                 receipt and they confirmed. params: { key, title, lines: [{ category,
//                 amount, date, vendor, invoice_number, description }] }. The same
//                 rules as filing it here: it goes to their manager on record, each
//                 line's category must be one of this workspace's, and their grade's
//                 cap for it applies. A category that needs a bill keeps the claim as
//                 a Draft: the original is attached here before it is sent. `key`
//                 makes asking twice return the first claim, never a second.
//
//   claim.decide  The person approves or rejects a claim waiting on them.
//                 params: { reference, decision: "approve" | "reject", comment,
//                 reason }. Only its current approver or an admin of this
//                 workspace, only while pending, through the same two-level
//                 workflow (manager, then finance) as the dashboard.
//
// claims.paid needs an active admin here whom AskMira also calls admin; the
// others need only an active member of this workspace, acting for themselves.

const MAX_PAID = 500;

async function claimsPaid(slug, me, params) {
  const refs = Array.isArray(params.references)
    ? [...new Set(params.references.map((r) => String(r || "").trim()).filter(Boolean))]
    : [];
  if (!refs.length || refs.length > MAX_PAID) {
    throw httpError(422, `Name between 1 and ${MAX_PAID} claims.`);
  }
  const paidOn = String(params.paid_on || "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(paidOn) || Number.isNaN(new Date(paidOn).getTime())) {
    throw httpError(422, "paid_on must be a date, YYYY-MM-DD.");
  }
  const note = clean(params.note, 300) || "Paid with salary in AskMira payroll";
  const { rows } = await pool.query(
    `SELECT e.* FROM expenses e
       JOIN employees s ON LOWER(s.email) = LOWER(e.submitter_email) AND s.tenant = $1
      WHERE e.unique_key = ANY($2::text[])`,
    [slug, refs],
  );
  const byRef = new Map(rows.map((row) => [row.unique_key, row]));
  const paid = [];
  const skipped = [];
  const now = new Date().toISOString();
  for (const ref of refs) {
    const row = byRef.get(ref);
    if (!row) {
      skipped.push({ reference: ref, reason: "Not a claim of this workspace." });
      continue;
    }
    if ((row.data?.PaymentStatus || "Unpaid") === "Paid") {
      skipped.push({ reference: ref, reason: "Already paid." });
      continue;
    }
    if (!/^approv/i.test(row.approval_status || "")) {
      skipped.push({ reference: ref, reason: "Not approved." });
      continue;
    }
    const data = {
      ...row.data,
      PaymentStatus: "Paid",
      PaymentInfo: {
        Method: "AskMira payroll",
        PaidAt: new Date(paidOn).toISOString(),
        PaidBy: me.email,
        Reference: note,
        Note: note,
      },
      LastActionAt: now,
      ApprovalHistory: [
        ...(Array.isArray(row.data?.ApprovalHistory) ? row.data.ApprovalHistory : []),
        {
          at: now,
          by: me.email,
          from: "Unpaid",
          to: "Paid",
          action_status: "Payment Recorded",
          comments: `${note} (${paidOn}).`,
        },
      ],
    };
    // Only while still unpaid, so two calls at once cannot both record it.
    const updated = await pool.query(
      `UPDATE expenses SET data = $1, updated_at = NOW()
        WHERE id = $2 AND COALESCE(data->>'PaymentStatus', 'Unpaid') <> 'Paid'`,
      [data, row.id],
    );
    if (updated.rowCount) paid.push(ref);
    else skipped.push({ reference: ref, reason: "Already paid." });
  }
  return { paid, skipped };
}

const masterExpense = require("./masterExpense");

const MAX_LINES = 20;
const MAX_AMOUNT = 10_000_000;
const DAY_MS = 24 * 60 * 60 * 1000;

function rupees(n) {
  return `₹${Number(n).toLocaleString("en-IN", { maximumFractionDigits: 2 })}`;
}

/** One claim line as typed, checked; or throws 422 saying what is wrong with it. */
function lineOf(raw, index, categories) {
  const where = `Line ${index + 1}`;
  const item = raw && typeof raw === "object" ? raw : {};
  const wanted = clean(item.category, 80);
  if (!wanted) throw httpError(422, `${where}: which category is it?`);
  const category = categories.find(
    (c) => c.name.toLowerCase() === wanted.toLowerCase() || (c.normalized || "").toLowerCase() === wanted.toLowerCase(),
  );
  if (!category) {
    const names = categories.map((c) => c.name).join(", ") || "none set up yet";
    throw httpError(422, `${where}: "${wanted}" is not a category here. These are: ${names}.`);
  }
  const amountText = String(item.amount ?? "").replace(/[,₹\s]/g, "");
  if (!/^\d+(\.\d{1,2})?$/.test(amountText) || Number(amountText) <= 0 || Number(amountText) > MAX_AMOUNT) {
    throw httpError(422, `${where}: the amount must be a positive number of rupees with at most two decimals, up to ${rupees(MAX_AMOUNT)}.`);
  }
  const day = String(item.date || "");
  const when = new Date(`${day}T00:00:00Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || Number.isNaN(when.getTime())) {
    throw httpError(422, `${where}: the bill's date must be YYYY-MM-DD.`);
  }
  if (when.getTime() > Date.now() + DAY_MS) throw httpError(422, `${where}: the bill's date is in the future.`);
  if (when.getTime() < Date.now() - 366 * DAY_MS) throw httpError(422, `${where}: the bill is more than a year old.`);
  return {
    category,
    amount: Number(amountText),
    line: {
      Category: category.name,
      ExpenseType: category.name,
      InvoiceAmount: Number(amountText),
      DocumentDate: day,
      PostingDate: new Date().toISOString().split("T")[0],
      VendorName: clean(item.vendor, 120) || undefined,
      InvoiceNumber: clean(item.invoice_number, 60) || undefined,
      BillNumber: clean(item.invoice_number, 60) || undefined,
      Description: clean(item.description, 500) || undefined,
      Narration: clean(item.description, 500) || clean(item.vendor, 120) || category.name,
      Currency: "INR",
      Source: "AskMira",
    },
  };
}

async function claimCreate(slug, me, params) {
  const key = String(params.key || "");
  if (!/^[A-Za-z0-9:_-]{6,80}$/.test(key)) throw httpError(422, "Every claim from AskMira needs its key.");
  const expenseId = `askmira:${key}`;
  const earlier = await pool.query(
    `SELECT * FROM expenses WHERE unique_key = $1 AND LOWER(submitter_email) = LOWER($2) LIMIT 1`,
    [expenseId, me.email],
  );
  if (earlier.rows[0]) {
    const saved = masterExpense.rowToShape(earlier.rows[0]);
    return { existing: true, claim: claimShape(saved), needs_bill: [] };
  }
  const title = clean(params.title, 200);
  if (!title || title.length < 2) throw httpError(422, "What is the claim for? Give it a short title.");
  const raw = Array.isArray(params.lines) ? params.lines : [];
  if (!raw.length || raw.length > MAX_LINES) throw httpError(422, `A claim has between 1 and ${MAX_LINES} lines.`);
  const { rows: categories } = await pool.query(
    `SELECT name, normalized, requires_bill FROM expense_categories WHERE slug = $1 AND enabled IS NOT FALSE ORDER BY name`,
    [slug],
  );
  const lines = raw.map((item, index) => lineOf(item, index, categories));

  // The person's grade caps each category, as when they file it here.
  const grade = me.grade ? String(me.grade) : "";
  if (grade) {
    const { rows: caps } = await pool.query(
      `SELECT normalized, cap_amount, is_actuals FROM tenant_policy_caps WHERE slug = $1 AND grade = $2`,
      [slug, grade],
    );
    const capOf = new Map(caps.map((c) => [String(c.normalized).toLowerCase(), c]));
    // One bill split into lines is still one bill: lines of the same category and
    // invoice number are added up before the cap is compared.
    const bills = new Map();
    lines.forEach(({ category, amount, line }, index) => {
      const invoice = String(line.InvoiceNumber || "").trim().toLowerCase();
      const key = `${category.name.toLowerCase()}|${invoice || `#${index}`}`;
      const bill = bills.get(key) || { category, amount: 0 };
      bill.amount = Math.round((bill.amount + amount) * 100) / 100;
      bills.set(key, bill);
    });
    for (const { category, amount } of bills.values()) {
      const cap = capOf.get(String(category.normalized || category.name).toLowerCase());
      const limit = cap ? Number(cap.cap_amount) : 0;
      if (cap && !cap.is_actuals && limit > 0 && amount > limit) {
        throw httpError(422, `${category.name} is capped at ${rupees(limit)} for grade ${grade}; this bill is ${rupees(amount)}.`);
      }
    }
  }

  const repeated = await earlierClaimsOf(slug, me.email, raw);
  if (repeated.length) {
    const first = repeated[0];
    throw httpError(409, `Line ${first.line}: this bill is already claimed in “${first.title}” (${first.status}). A bill is claimed once.`);
  }

  const routed = await masterExpense.resolveApprover(me.email, null);
  if (routed.error) throw httpError(422, routed.error);
  const needsBill = [...new Set(lines.filter((l) => l.category.requires_bill !== false).map((l) => l.category.name))];
  const saved = await masterExpense.createExpense(
    {
      ExpenseTitle: title,
      ExpenseId: expenseId,
      SubmitterEmail: me.email,
      SubmitterName: me.name || me.email,
      ApproverEmail: routed.approver,
      ApprovalStatus: needsBill.length ? "Draft" : "Pending",
      ExpenseData: lines.map((l) => l.line),
      Source: "AskMira",
    },
    {
      comment: needsBill.length
        ? `Filed from Ask Mira in AskMira. Kept as a draft: attach the bill for ${needsBill.join(", ")}, then send it.`
        : "Filed from Ask Mira in AskMira and sent for approval.",
      notifyDrafts: false,
    },
  );
  return { existing: false, claim: claimShape(saved), needs_bill: needsBill };
}

function claimShape(saved) {
  return {
    reference: saved.ExpenseId,
    title: saved.ExpenseTitle,
    status: saved.ApprovalStatus,
    // Rupees to the paisa: a float sum of 2838.60 + 4609.29 + 46.11 is 7493.999…
    amount: (Math.round(Number(saved.TotalAmount || 0) * 100) / 100).toFixed(2),
    approver: saved.ApproverEmail,
  };
}

async function claimDecide(slug, me, params) {
  const id = clean(params.id, 40);
  const reference = clean(params.reference, 120);
  const decision = String(params.decision || "");
  if (!id && !reference) throw httpError(422, "Which claim? Give its id.");
  if (!["approve", "reject"].includes(decision)) throw httpError(422, "decision is approve or reject.");
  // The row AskMira showed, by its own id; a reference alone must name one claim only.
  const { rows } = await pool.query(
    `SELECT e.* FROM expenses e
       JOIN employees s ON LOWER(s.email) = LOWER(e.submitter_email) AND s.tenant = $1
      WHERE ${id ? "e.id = $2" : "e.unique_key = $2"}
      LIMIT 2`,
    [slug, id || reference],
  );
  if (rows.length > 1) throw httpError(409, "That reference names more than one claim. Decide it in ExpGenie.");
  const row = rows[0];
  if (!row) throw httpError(404, "No claim of this workspace has that reference.");
  if (reference && id && row.unique_key !== reference) throw httpError(409, "That claim has changed. Look it up again.");
  if (normEmail(row.submitter_email) === normEmail(me.email)) {
    throw httpError(403, "You can't decide your own claim.");
  }
  // Decided as the step it waits at: only its current approver, never an admin's
  // override (that is the dashboard's), so a claim that moved on to finance is not
  // finalised by the manager who was shown it before.
  if (normEmail(row.approver_email) !== normEmail(me.email)) {
    throw httpError(403, "This claim isn't waiting on you: only its current approver decides it from Ask Mira.");
  }
  if (!/^pending/i.test(String(row.approval_status || ""))) {
    throw httpError(409, `This claim is ${row.approval_status || "not pending"}, not waiting for approval.`);
  }
  const comment = clean(params.comment, 500);
  const reason = clean(params.reason, 120) || (decision === "reject" ? clean(comment, 120) : "");
  if (decision === "reject" && !reason) {
    throw httpError(422, "Say why it is rejected: the submitter reads it.");
  }
  const updated = await masterExpense.updateStatus(
    row.id,
    {
      ApprovalStatus: decision === "approve" ? "Approved" : "Rejected",
      UpdatedBy: me.email,
      Comments: comment ? `${comment} (from Ask Mira)` : "Decided from Ask Mira",
      RejectionReason: reason || undefined,
    },
    { expectApprover: me.email },
  );
  return {
    claim: {
      reference: updated.ExpenseId,
      title: updated.ExpenseTitle,
      status: updated.ApprovalStatus,
      // Approved by the manager with finance still to sign, it waits on finance now.
      next_approver: updated.ApprovalStatus === "Pending" ? updated.ApproverEmail : null,
    },
  };
}

const ACTIONS = {
  "claims.paid": { run: claimsPaid, admin: true },
  "claim.create": { run: claimCreate, admin: false },
  "claim.decide": { run: claimDecide, admin: false },
};

integrationRouter.post(
  "/act",
  handle(async (req) => {
    const claims = await provisionClaims(req, "act");
    const kind = String(req.body.kind || "");
    const action = Object.prototype.hasOwnProperty.call(ACTIONS, kind) ? ACTIONS[kind] : null;
    if (!action) throw httpError(422, "Unknown action.");
    if (!claims.jti || typeof claims.exp !== "number") throw httpError(401, "This AskMira request is not valid.");
    await pool.query(`DELETE FROM askmira_launches WHERE expires_at < NOW() - INTERVAL '5 minutes'`);
    const fresh = await pool.query(
      `INSERT INTO askmira_launches (jti, expires_at) VALUES ($1, to_timestamp($2))
       ON CONFLICT (jti) DO NOTHING`,
      [String(claims.jti).slice(0, 64), claims.exp],
    );
    if (!fresh.rowCount) throw httpError(401, "This request was already carried out.");

    const slug = await linkedSlug(String(req.body.tenant_id));
    if (!slug) throw httpError(404, "This workspace is not linked here yet.");
    await refuseBlocked(slug);
    const actor = req.body.actor && typeof req.body.actor === "object" ? req.body.actor : {};
    const email = normEmail(actor.email);
    const { rows } = await pool.query(
      `SELECT email, name, role, grade, tenant, deactivated_at FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [email],
    );
    const me = rows[0];
    if (!EMAIL_RE.test(email) || !me || me.tenant !== slug || me.deactivated_at || me.role === "super_admin") {
      throw httpError(403, "You don't have an ExpGenie account in this workspace yet. Open ExpGenie once from AskMira, then ask again.");
    }
    if (action.admin && (me.role !== "admin" || String(actor.role || "") !== "admin")) {
      throw httpError(403, "Recording payroll payments here is for an ExpGenie admin of this workspace.");
    }
    const params = req.body.params && typeof req.body.params === "object" ? req.body.params : {};
    const result = await action.run(slug, me, params);
    console.log(`[AskMira] act ${kind} for ${slug} by ${email}`);
    return { kind, ...result };
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

// ── Connecting (from AskMira, by an admin of this tenant) ───────────────────
//
// Like "Sign in with…": an admin of a workspace in AskMira presses Connect
// there, lands on the dashboard's /connect/askmira, signs in and presses Allow.
// That makes a one-time code bound to their tenant and to a challenge only
// AskMira's server can answer (PKCE); AskMira's server swaps code + verifier for
// the tenant's own secret (/connect/token). The secret reaches only that one
// tenant's records, and either side can disconnect.

const CODE_LIFETIME_MS = 5 * 60 * 1000;
const CALLBACK_PATH = "/settings/connectors/callback";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PKCE_RE = /^[A-Za-z0-9_-]{43,128}$/;

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

function requireTenantAdmin(req) {
  if (req.auth?.role !== "admin" || !req.auth.tenant) {
    throw httpError(403, "Only an admin of a workspace connects it to AskMira.");
  }
  return req.auth.tenant;
}

// The AskMira that is asking, from where it wants the answer sent; refuses anything odd.
function askmiraOrigin(redirectUri) {
  let url;
  try {
    url = new URL(String(redirectUri || ""));
  } catch {
    throw httpError(422, "That is not an AskMira connect link.");
  }
  const local = ["localhost", "127.0.0.1"].includes(url.hostname);
  if (
    !["https:", "http:"].includes(url.protocol) ||
    (url.protocol === "http:" && !local) ||
    url.pathname.replace(/\/+$/, "") !== CALLBACK_PATH ||
    url.search ||
    url.hash
  ) {
    throw httpError(422, "That is not an AskMira connect link.");
  }
  const allowed = String(process.env.ASKMIRA_ALLOWED_ORIGINS || "")
    .split(",")
    .map((o) => o.trim().replace(/\/+$/, ""))
    .filter(Boolean);
  if (allowed.length && !allowed.includes(url.origin)) {
    throw httpError(403, "This AskMira is not one this server connects to.");
  }
  return url.origin;
}

async function connectionRead(slug) {
  const { rows } = await pool.query(
    `SELECT askmira_name, askmira_origin, connected_at FROM askmira_links
      WHERE slug = $1 AND secret_nonce IS NOT NULL`,
    [slug],
  );
  const row = rows[0];
  return {
    tenant: slug,
    connected: Boolean(row),
    askmira_workspace: row?.askmira_name || null,
    askmira_origin: row?.askmira_origin || null,
    connected_at: row?.connected_at ? new Date(row.connected_at).toISOString() : null,
  };
}

// Whether the caller's tenant is connected to an AskMira workspace, and which.
connectionRouter.get(
  "/",
  handle(async (req) => connectionRead(requireTenantAdmin(req))),
);

// The admin pressed Allow: a one-time code for AskMira, bound to their tenant.
connectionRouter.post(
  "/approve",
  handle(async (req) => {
    const slug = requireTenantAdmin(req);
    if (serverKey().length < 32) throw httpError(409, "Set a long AUTH_JWT_SECRET on this server first.");
    const tenantId = String(req.body?.tenant_id || "").toLowerCase();
    const challenge = String(req.body?.challenge || "");
    const state = String(req.body?.state || "");
    const name = clean(req.body?.tenant_name);
    if (!UUID_RE.test(tenantId) || !PKCE_RE.test(challenge) || !state || state.length > 2000 || !name) {
      throw httpError(422, "That is not an AskMira connect link.");
    }
    const origin = askmiraOrigin(req.body?.redirect_uri);
    const { rows: links } = await pool.query(
      `SELECT askmira_tenant_id, slug FROM askmira_links WHERE slug = $1 OR askmira_tenant_id = $2`,
      [slug, tenantId],
    );
    if (links.some((l) => l.slug === slug && l.askmira_tenant_id !== tenantId)) {
      throw httpError(409, "Your workspace is already connected to another AskMira workspace. Disconnect it first.");
    }
    if (links.some((l) => l.askmira_tenant_id === tenantId && l.slug !== slug)) {
      throw httpError(409, "That AskMira workspace is already connected to another workspace here.");
    }
    const code = crypto.randomBytes(32).toString("base64url");
    await pool.query(`DELETE FROM askmira_connect_codes WHERE expires_at < NOW()`);
    await pool.query(
      `INSERT INTO askmira_connect_codes
         (code_hash, slug, askmira_tenant_id, askmira_name, askmira_origin, challenge, user_email, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [sha256(code), slug, tenantId, name, origin, challenge, req.auth.email, new Date(Date.now() + CODE_LIFETIME_MS)],
    );
    console.log(`[AskMira] ${slug} approved a connection to workspace ${tenantId} at ${origin}`);
    const query = new URLSearchParams({ code, state, product: "expense" });
    return { redirect_to: `${String(req.body.redirect_uri).replace(/\/+$/, "")}?${query}` };
  }),
);

// AskMira's server swaps the code (and the verifier only it holds) for the tenant's secret.
integrationRouter.post(
  "/connect/token",
  handle(async (req) => {
    const code = String(req.body?.code || "");
    const verifier = String(req.body?.verifier || "");
    const tenantId = String(req.body?.tenant_id || "").toLowerCase();
    const refused = httpError(400, "This connect code is not valid or has expired.");
    if (!code || code.length > 200 || !PKCE_RE.test(verifier)) throw refused;
    // One use, whatever happens next.
    const { rows } = await pool.query(
      `UPDATE askmira_connect_codes SET used_at = NOW()
        WHERE code_hash = $1 AND used_at IS NULL AND expires_at > NOW()
        RETURNING *`,
      [sha256(code)],
    );
    const row = rows[0];
    if (!row) throw refused;
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    if (
      row.askmira_tenant_id !== tenantId ||
      challenge.length !== row.challenge.length ||
      !crypto.timingSafeEqual(Buffer.from(challenge), Buffer.from(row.challenge))
    ) {
      throw refused;
    }
    const nonce = crypto.randomBytes(32).toString("base64url");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const { rows: clash } = await client.query(
        `SELECT 1 FROM askmira_links WHERE (slug = $1) <> (askmira_tenant_id = $2)
            AND (slug = $1 OR askmira_tenant_id = $2)`,
        [row.slug, tenantId],
      );
      if (clash.length) throw httpError(409, "That AskMira workspace is already connected to another workspace here.");
      await client.query(
        `INSERT INTO askmira_links (askmira_tenant_id, slug, secret_nonce, askmira_name, askmira_origin, connected_at, connected_by)
         VALUES ($1, $2, $3, $4, $5, NOW(), $6)
         ON CONFLICT (askmira_tenant_id) DO UPDATE
           SET secret_nonce = EXCLUDED.secret_nonce, askmira_name = EXCLUDED.askmira_name,
               askmira_origin = EXCLUDED.askmira_origin, connected_at = NOW(), connected_by = EXCLUDED.connected_by`,
        [tenantId, row.slug, nonce, row.askmira_name, row.askmira_origin, row.user_email],
      );
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
    console.log(`[AskMira] ${row.slug} connected to workspace ${tenantId}`);
    return {
      product: "expense",
      brand: "ExpenseGenie",
      secret: derive(row.slug, nonce),
      external_ref: row.slug,
      organization: row.slug,
    };
  }),
);

// Disconnect from this side: AskMira's secret for this tenant stops working at once.
connectionRouter.delete(
  "/",
  handle(async (req) => {
    const slug = requireTenantAdmin(req);
    await pool.query(`DELETE FROM askmira_links WHERE slug = $1`, [slug]);
    console.log(`[AskMira] ${slug} disconnected by ${req.auth.email}`);
    return connectionRead(slug);
  }),
);

// AskMira disconnected: forget this workspace's secret here too.
integrationRouter.post(
  "/connect/revoke",
  handle(async (req) => {
    const claims = await provisionClaims(req, "revoke");
    await pool.query(`DELETE FROM askmira_links WHERE askmira_tenant_id = $1`, [claims.sub]);
    console.log(`[AskMira] workspace ${claims.sub} disconnected from AskMira`);
    return { disconnected: true };
  }),
);

module.exports = { integrationRouter, authRouter, connectionRouter };
