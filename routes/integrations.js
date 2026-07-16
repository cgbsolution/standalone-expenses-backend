// Per-tenant integration configuration (SAP ERP posting + HRMS employee sync).
//
//   GET  /integrations/:slug            → this tenant's config (secrets masked)
//   PUT  /integrations/:slug            → upsert config (secrets preserved if blank)
//   POST /integrations/:slug/:type/test → reachability check for sap|hrms
//
// Secrets (SAP password, HRMS secret) are stored in the JSONB blob but NEVER
// returned. The API instead returns `<field>Set: true/false` so the UI can show
// "saved" without exposing the value, and a blank secret on PUT keeps the old one.

const express = require("express");
const pool = require("../dbClient");

const router = express.Router();

// Whitelisted fields per provider. `secret: true` marks a write-only field.
const SAP_FIELDS = [
  { key: "enabled" },
  { key: "baseUrl" },
  { key: "authType" }, // 'basic' | 'oauth2'
  { key: "username" },
  { key: "password", secret: true },
  { key: "companyCode" },
  { key: "glAccount" },
  { key: "costCenter" },
  { key: "taxCode" },
];
const HRMS_FIELDS = [
  { key: "enabled" },
  { key: "baseUrl" },
  { key: "authType" }, // 'basic' | 'apikey'
  { key: "username" },
  { key: "secret", secret: true },
  { key: "employeeEndpoint" },
  { key: "autoSync" },
];

const FIELDS_BY_TYPE = { sap: SAP_FIELDS, hrms: HRMS_FIELDS };

// Strip secrets from a stored blob; expose a boolean `<field>Set` instead.
function maskProvider(stored, fields) {
  const out = {};
  const src = stored || {};
  for (const f of fields) {
    if (f.secret) {
      out[`${f.key}Set`] = Boolean(src[f.key]);
    } else {
      out[f.key] = src[f.key] ?? (f.key === "enabled" || f.key === "autoSync" ? false : "");
    }
  }
  return out;
}

// Merge an incoming (client) blob into the existing stored blob, honoring the
// whitelist and preserving secrets when the client sends them blank.
function mergeProvider(existing, incoming, fields) {
  const base = { ...(existing || {}) };
  const inc = incoming || {};
  for (const f of fields) {
    if (!(f.key in inc)) continue;
    const val = inc[f.key];
    if (f.secret) {
      // Only overwrite a secret when a non-empty value is provided.
      if (val !== undefined && val !== null && String(val).length > 0) {
        base[f.key] = String(val);
      }
    } else if (f.key === "enabled" || f.key === "autoSync") {
      base[f.key] = Boolean(val);
    } else {
      base[f.key] = val == null ? "" : String(val);
    }
  }
  return base;
}

async function loadRow(slug) {
  const { rows } = await pool.query(
    `SELECT slug, sap, hrms, updated_at FROM tenant_integrations WHERE slug = $1`,
    [slug],
  );
  return rows[0] || null;
}

/**
 * @swagger
 * tags:
 *   name: Integrations
 *   description: Per-tenant SAP / HRMS integration configuration
 */

/**
 * @swagger
 * /integrations/{slug}:
 *   get:
 *     summary: Get a tenant's integration config (secrets masked)
 *     tags: [Integrations]
 *     parameters:
 *       - in: path
 *         name: slug
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: Integration config }
 */
router.get("/:slug", async (req, res) => {
  try {
    const row = await loadRow(req.params.slug);
    return res.json({
      slug: req.params.slug,
      sap: maskProvider(row?.sap, SAP_FIELDS),
      hrms: maskProvider(row?.hrms, HRMS_FIELDS),
      updatedAt: row?.updated_at || null,
    });
  } catch (error) {
    console.error("Error fetching integrations:", error);
    return res.status(500).json({ error: "Failed to fetch integrations." });
  }
});

/**
 * @swagger
 * /integrations/{slug}:
 *   put:
 *     summary: Upsert a tenant's integration config
 *     tags: [Integrations]
 *     parameters:
 *       - in: path
 *         name: slug
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               sap: { type: object }
 *               hrms: { type: object }
 *     responses:
 *       200: { description: Saved config (secrets masked) }
 */
router.put("/:slug", async (req, res) => {
  const slug = req.params.slug;
  if (!slug) return res.status(400).json({ error: "slug is required" });
  try {
    const existing = await loadRow(slug);
    const sap = mergeProvider(existing?.sap, req.body?.sap, SAP_FIELDS);
    const hrms = mergeProvider(existing?.hrms, req.body?.hrms, HRMS_FIELDS);

    const { rows } = await pool.query(
      `INSERT INTO tenant_integrations (slug, sap, hrms, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (slug)
       DO UPDATE SET sap = $2, hrms = $3, updated_at = NOW()
       RETURNING slug, sap, hrms, updated_at`,
      [slug, sap, hrms],
    );
    const row = rows[0];
    return res.json({
      slug,
      sap: maskProvider(row.sap, SAP_FIELDS),
      hrms: maskProvider(row.hrms, HRMS_FIELDS),
      updatedAt: row.updated_at,
    });
  } catch (error) {
    console.error("Error saving integrations:", error);
    return res.status(500).json({ error: "Failed to save integrations." });
  }
});

/**
 * @swagger
 * /integrations/{slug}/{type}/test:
 *   post:
 *     summary: Reachability check for a provider endpoint (sap|hrms)
 *     tags: [Integrations]
 *     parameters:
 *       - in: path
 *         name: slug
 *         required: true
 *         schema: { type: string }
 *       - in: path
 *         name: type
 *         required: true
 *         schema: { type: string, enum: [sap, hrms] }
 *     responses:
 *       200: { description: "{ ok, status?, message }" }
 */
router.post("/:slug/:type/test", async (req, res) => {
  const { slug, type } = req.params;
  const fields = FIELDS_BY_TYPE[type];
  if (!fields) return res.status(400).json({ error: "type must be 'sap' or 'hrms'" });

  try {
    const row = await loadRow(slug);
    // Allow testing an unsaved URL passed in the body (live form value).
    const baseUrl = (req.body?.baseUrl || row?.[type]?.baseUrl || "").trim();
    if (!baseUrl) {
      return res.json({ ok: false, message: "No endpoint URL configured." });
    }
    if (!/^https?:\/\//i.test(baseUrl)) {
      return res.json({ ok: false, message: "Endpoint must start with http(s)://" });
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    try {
      const started = Date.now();
      const resp = await fetch(baseUrl, { method: "GET", signal: ctrl.signal });
      clearTimeout(timer);
      // Any HTTP response (even 401/404) means the host is reachable.
      return res.json({
        ok: true,
        status: resp.status,
        latencyMs: Date.now() - started,
        message: `Reachable — responded HTTP ${resp.status}.`,
      });
    } catch (e) {
      clearTimeout(timer);
      return res.json({
        ok: false,
        message:
          e.name === "AbortError"
            ? "Timed out after 8s — host did not respond."
            : `Could not reach endpoint: ${e.message}`,
      });
    }
  } catch (error) {
    console.error("Error testing integration:", error);
    return res.status(500).json({ error: "Failed to test connection." });
  }
});

module.exports = router;
