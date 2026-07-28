// Workspace / platform configuration, keyed by tenant slug.
// The reserved slug '__platform__' holds super-admin platform settings.
//   GET /tenant-config/:slug
//   PUT /tenant-config/:slug   { config: {...} }  (shallow-merged)

const express = require("express");
const pool = require("../dbClient");

const router = express.Router();

const DEFAULTS = {
  currency: "INR",
  fiscalYearStart: "April",
  weekStart: "Monday",
  receiptRequired: true,
  perClaimLimit: 0,
  autoApproveUnder: 0,
  notifyByEmail: true,
  brandColor: "",
  // Super-admin only. When a tenant has no SAP connection, payments can't be
  // posted automatically — turning this on lets that tenant's finance approver
  // tick "payment done" by hand after final approval. See POST
  // /master-expense/:id/payment, which refuses unless this flag is true.
  manualPaymentEnabled: false,
};

const ALLOWED = Object.keys(DEFAULTS);

router.get("/:slug", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT config, updated_at FROM tenant_config WHERE slug = $1`,
      [req.params.slug],
    );
    return res.json({
      slug: req.params.slug,
      config: { ...DEFAULTS, ...(rows[0]?.config || {}) },
      updatedAt: rows[0]?.updated_at || null,
    });
  } catch (e) {
    console.error("Error fetching config:", e);
    return res.status(500).json({ error: "Failed to fetch config." });
  }
});

router.put("/:slug", async (req, res) => {
  const incoming = req.body?.config || req.body || {};
  const clean = {};
  for (const k of ALLOWED) if (k in incoming) clean[k] = incoming[k];
  try {
    const { rows } = await pool.query(
      `INSERT INTO tenant_config (slug, config, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (slug)
       DO UPDATE SET config = tenant_config.config || $2, updated_at = NOW()
       RETURNING config, updated_at`,
      [req.params.slug, clean],
    );
    return res.json({
      slug: req.params.slug,
      config: { ...DEFAULTS, ...rows[0].config },
      updatedAt: rows[0].updated_at,
    });
  } catch (e) {
    console.error("Error saving config:", e);
    return res.status(500).json({ error: "Failed to save config." });
  }
});

module.exports = router;
