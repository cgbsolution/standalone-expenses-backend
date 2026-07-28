// Copy a tenant's master config — expense categories (+ GL codes & flags),
// output/policy rules, and grade-wise policy caps — from one tenant to another.
// Idempotent (upserts on the natural keys), so safe to re-run.
//
// Run:  node scripts/copy-tenant-config.js <fromSlug> <toSlug>
//   e.g. node scripts/copy-tenant-config.js xeltrion cgb-solutions

require("dotenv").config();
const pool = require("../dbClient");

const FROM = (process.argv[2] || "").toLowerCase();
const TO = (process.argv[3] || "").toLowerCase();

if (!FROM || !TO) {
  console.error("Usage: node scripts/copy-tenant-config.js <fromSlug> <toSlug>");
  process.exit(1);
}
if (FROM === TO) {
  console.error("Source and target must differ.");
  process.exit(1);
}

async function main() {
  console.log(`Copying master config: ${FROM} → ${TO}`);

  const cats = await pool.query(
    `INSERT INTO expense_categories
       (slug, name, color, icon, monthly_budget, gl_account, normalized,
        requires_bill, excluded_from_auto_approve, enabled, gl_project, gl_crm)
     SELECT $2, name, color, icon, monthly_budget, gl_account, normalized,
            requires_bill, excluded_from_auto_approve, enabled, gl_project, gl_crm
       FROM expense_categories WHERE slug = $1
     ON CONFLICT (slug, name) DO UPDATE SET
       color = EXCLUDED.color, icon = EXCLUDED.icon, monthly_budget = EXCLUDED.monthly_budget,
       gl_account = EXCLUDED.gl_account, normalized = EXCLUDED.normalized,
       requires_bill = EXCLUDED.requires_bill,
       excluded_from_auto_approve = EXCLUDED.excluded_from_auto_approve,
       enabled = EXCLUDED.enabled, gl_project = EXCLUDED.gl_project, gl_crm = EXCLUDED.gl_crm`,
    [FROM, TO],
  );
  console.log(`  categories: ${cats.rowCount}`);

  const rules = await pool.query(
    `INSERT INTO tenant_rules (slug, rule_id, enabled, priority, rule_group, rule_type, params)
     SELECT $2, rule_id, enabled, priority, rule_group, rule_type, params
       FROM tenant_rules WHERE slug = $1
     ON CONFLICT (slug, rule_id) DO UPDATE SET
       enabled = EXCLUDED.enabled, priority = EXCLUDED.priority,
       rule_group = EXCLUDED.rule_group, rule_type = EXCLUDED.rule_type, params = EXCLUDED.params`,
    [FROM, TO],
  );
  console.log(`  rules: ${rules.rowCount}`);

  const caps = await pool.query(
    `INSERT INTO tenant_policy_caps (slug, normalized, grade, cap_amount, is_actuals, self_approve)
     SELECT $2, normalized, grade, cap_amount, is_actuals, self_approve
       FROM tenant_policy_caps WHERE slug = $1
     ON CONFLICT (slug, normalized, grade) DO UPDATE SET
       cap_amount = EXCLUDED.cap_amount, is_actuals = EXCLUDED.is_actuals,
       self_approve = EXCLUDED.self_approve`,
    [FROM, TO],
  );
  console.log(`  policy caps: ${caps.rowCount}`);

  if (cats.rowCount + rules.rowCount + caps.rowCount === 0) {
    console.warn(`Nothing copied — does tenant "${FROM}" have any config seeded?`);
  }
  console.log("Done.");
  await pool.end();
}

main().catch(async (e) => {
  console.error("Copy failed:", e.message);
  try { await pool.end(); } catch {}
  process.exit(1);
});
