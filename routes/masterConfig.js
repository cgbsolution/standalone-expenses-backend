// Read-only master config (output/policy rules + grade-wise policy caps) that the
// chatbot enforces and the dashboard displays.
//   GET /master-config/:slug  → { rules: [...], policyCaps: [...] }

const express = require("express");
const pool = require("../dbClient");

const router = express.Router();

router.get("/:slug", async (req, res) => {
  const { slug } = req.params;
  try {
    const [rules, caps] = await Promise.all([
      pool.query(
        `SELECT rule_id, enabled, priority, rule_group, rule_type, params
           FROM tenant_rules WHERE slug = $1 ORDER BY priority ASC, rule_id ASC`,
        [slug],
      ),
      pool.query(
        `SELECT normalized, grade, cap_amount, is_actuals, self_approve
           FROM tenant_policy_caps WHERE slug = $1
          ORDER BY normalized ASC, cap_amount ASC`,
        [slug],
      ),
    ]);
    return res.json({
      rules: rules.rows.map((r) => ({
        ruleId: r.rule_id,
        enabled: r.enabled,
        priority: r.priority,
        ruleGroup: r.rule_group,
        ruleType: r.rule_type,
        params: r.params || {},
      })),
      policyCaps: caps.rows.map((c) => ({
        normalized: c.normalized,
        grade: c.grade,
        capAmount: Number(c.cap_amount) || 0,
        isActuals: c.is_actuals === true,
        selfApprove: c.self_approve === true,
      })),
    });
  } catch (error) {
    console.error("Error fetching master config:", error);
    return res.status(500).json({ error: "Failed to fetch master config." });
  }
});

module.exports = router;
