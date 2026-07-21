// Per-tenant master config the chatbot enforces: output/policy rules
// (tenant_rules) + grade-wise policy caps (tenant_policy_caps).
//
//   GET    /master-config/:slug                     → { rules: [...], policyCaps: [...] }
//   POST   /master-config/:slug/policy-caps          create/upsert a cap
//   PUT    /master-config/:slug/policy-caps/:id      update a cap
//   DELETE /master-config/:slug/policy-caps/:id      remove a cap
//   POST   /master-config/:slug/rules                create/upsert a rule
//   PUT    /master-config/:slug/rules/:id            update a rule
//   DELETE /master-config/:slug/rules/:id            remove a rule
//
// The bot (bot-backend-source) reads these per-tenant tables and layers them
// over the global master data ("inherit global + override"). Edits here take
// effect on the bot after its master-data refresh interval, or immediately via
// the bot's POST /reload-master-data.

const express = require("express");
const pool = require("../dbClient");

const router = express.Router();

// ---- shapes -------------------------------------------------------------

function shapeCap(c) {
  return {
    id: c.id,
    slug: c.slug,
    normalized: c.normalized,
    grade: c.grade,
    capAmount: Number(c.cap_amount) || 0,
    isActuals: c.is_actuals === true,
    selfApprove: c.self_approve === true,
  };
}

function shapeRule(r) {
  return {
    id: r.id,
    slug: r.slug,
    ruleId: r.rule_id,
    enabled: r.enabled !== false,
    priority: Number(r.priority) || 0,
    ruleGroup: r.rule_group || "",
    ruleType: r.rule_type || "",
    params: r.params || {},
  };
}

function parseParams(params) {
  if (params == null) return {};
  if (typeof params === "string") {
    try {
      return JSON.parse(params) || {};
    } catch {
      return {};
    }
  }
  return params;
}

// ---- read ---------------------------------------------------------------

router.get("/:slug", async (req, res) => {
  const { slug } = req.params;
  try {
    const [rules, caps] = await Promise.all([
      pool.query(
        `SELECT id, slug, rule_id, enabled, priority, rule_group, rule_type, params
           FROM tenant_rules WHERE slug = $1 ORDER BY priority ASC, rule_id ASC`,
        [slug],
      ),
      pool.query(
        `SELECT id, slug, normalized, grade, cap_amount, is_actuals, self_approve
           FROM tenant_policy_caps WHERE slug = $1
          ORDER BY normalized ASC, grade ASC, cap_amount ASC`,
        [slug],
      ),
    ]);
    return res.json({
      rules: rules.rows.map(shapeRule),
      policyCaps: caps.rows.map(shapeCap),
    });
  } catch (error) {
    console.error("Error fetching master config:", error);
    return res.status(500).json({ error: "Failed to fetch master config." });
  }
});

// ---- policy caps CRUD ---------------------------------------------------

router.post("/:slug/policy-caps", async (req, res) => {
  const { slug } = req.params;
  const { normalized, grade, capAmount, isActuals, selfApprove } = req.body || {};
  if (!slug || !normalized || !grade) {
    return res.status(400).json({ error: "slug, normalized and grade are required" });
  }
  try {
    // Upsert on the natural key so re-adding the same (category, grade) edits it
    // instead of failing the unique constraint.
    const { rows } = await pool.query(
      `INSERT INTO tenant_policy_caps (slug, normalized, grade, cap_amount, is_actuals, self_approve)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (slug, normalized, grade) DO UPDATE SET
         cap_amount   = EXCLUDED.cap_amount,
         is_actuals   = EXCLUDED.is_actuals,
         self_approve = EXCLUDED.self_approve
       RETURNING *`,
      [
        slug,
        String(normalized).trim(),
        String(grade).trim(),
        Number(capAmount) || 0,
        isActuals === true,
        selfApprove !== false,
      ],
    );
    return res.status(201).json(shapeCap(rows[0]));
  } catch (e) {
    console.error("Error creating policy cap:", e);
    return res.status(500).json({ error: "Failed to save policy cap." });
  }
});

router.put("/:slug/policy-caps/:id", async (req, res) => {
  const { normalized, grade, capAmount, isActuals, selfApprove } = req.body || {};
  try {
    const { rows } = await pool.query(
      `UPDATE tenant_policy_caps
          SET normalized   = COALESCE($2, normalized),
              grade        = COALESCE($3, grade),
              cap_amount   = COALESCE($4, cap_amount),
              is_actuals   = COALESCE($5, is_actuals),
              self_approve = COALESCE($6, self_approve)
        WHERE id = $1 RETURNING *`,
      [
        req.params.id,
        normalized == null ? null : String(normalized).trim(),
        grade == null ? null : String(grade).trim(),
        capAmount == null ? null : Number(capAmount),
        isActuals == null ? null : isActuals === true,
        selfApprove == null ? null : selfApprove === true,
      ],
    );
    if (!rows.length) return res.status(404).json({ error: "Not found" });
    return res.json(shapeCap(rows[0]));
  } catch (e) {
    console.error("Error updating policy cap:", e);
    return res.status(500).json({ error: "Failed to update policy cap." });
  }
});

router.delete("/:slug/policy-caps/:id", async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      `DELETE FROM tenant_policy_caps WHERE id = $1`,
      [req.params.id],
    );
    if (!rowCount) return res.status(404).json({ error: "Not found" });
    return res.json({ deleted: true });
  } catch (e) {
    console.error("Error deleting policy cap:", e);
    return res.status(500).json({ error: "Failed to delete policy cap." });
  }
});

// ---- rules CRUD ---------------------------------------------------------

router.post("/:slug/rules", async (req, res) => {
  const { slug } = req.params;
  const { ruleId, enabled, priority, ruleGroup, ruleType, params } = req.body || {};
  if (!slug || !ruleId) {
    return res.status(400).json({ error: "slug and ruleId are required" });
  }
  try {
    const { rows } = await pool.query(
      `INSERT INTO tenant_rules (slug, rule_id, enabled, priority, rule_group, rule_type, params)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (slug, rule_id) DO UPDATE SET
         enabled    = EXCLUDED.enabled,
         priority   = EXCLUDED.priority,
         rule_group = EXCLUDED.rule_group,
         rule_type  = EXCLUDED.rule_type,
         params     = EXCLUDED.params
       RETURNING *`,
      [
        slug,
        String(ruleId).trim(),
        enabled !== false,
        Number(priority) || 0,
        ruleGroup || "",
        ruleType || "",
        parseParams(params),
      ],
    );
    return res.status(201).json(shapeRule(rows[0]));
  } catch (e) {
    console.error("Error creating rule:", e);
    return res.status(500).json({ error: "Failed to save rule." });
  }
});

router.put("/:slug/rules/:id", async (req, res) => {
  const { ruleId, enabled, priority, ruleGroup, ruleType, params } = req.body || {};
  try {
    const { rows } = await pool.query(
      `UPDATE tenant_rules
          SET rule_id    = COALESCE($2, rule_id),
              enabled    = COALESCE($3, enabled),
              priority   = COALESCE($4, priority),
              rule_group = COALESCE($5, rule_group),
              rule_type  = COALESCE($6, rule_type),
              params     = COALESCE($7, params)
        WHERE id = $1 RETURNING *`,
      [
        req.params.id,
        ruleId == null ? null : String(ruleId).trim(),
        enabled == null ? null : enabled !== false,
        priority == null ? null : Number(priority),
        ruleGroup == null ? null : ruleGroup,
        ruleType == null ? null : ruleType,
        params == null ? null : parseParams(params),
      ],
    );
    if (!rows.length) return res.status(404).json({ error: "Not found" });
    return res.json(shapeRule(rows[0]));
  } catch (e) {
    console.error("Error updating rule:", e);
    return res.status(500).json({ error: "Failed to update rule." });
  }
});

router.delete("/:slug/rules/:id", async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      `DELETE FROM tenant_rules WHERE id = $1`,
      [req.params.id],
    );
    if (!rowCount) return res.status(404).json({ error: "Not found" });
    return res.json({ deleted: true });
  } catch (e) {
    console.error("Error deleting rule:", e);
    return res.status(500).json({ error: "Failed to delete rule." });
  }
});

module.exports = router;
