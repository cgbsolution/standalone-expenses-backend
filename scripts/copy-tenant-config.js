// Copy a tenant's master config — expense categories (+ GL codes & flags),
// output/policy rules, and grade-wise policy caps — from one tenant to another.
// Idempotent (upserts on the natural keys), so safe to re-run.
//
// Run:  node scripts/copy-tenant-config.js <fromSlug> <toSlug> [--categories-only] [--dry-run]
//   e.g. node scripts/copy-tenant-config.js xeltrion cgb-solutions
//        node scripts/copy-tenant-config.js cgb-solutions artboxsolutions --categories-only
//
//   --categories-only  copy categories (+ GL codes & flags) but NOT rules or
//                      grade-wise caps. Use when the target tenant hasn't set
//                      employee grades yet, or runs in No-Policy mode — caps
//                      keyed by grade would never match anything there.
//   --dry-run          report what would be copied, write nothing.

require("dotenv").config();
const pool = require("../dbClient");

const args = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const flags = new Set(process.argv.slice(2).filter((a) => a.startsWith("--")));
const FROM = (args[0] || "").toLowerCase();
const TO = (args[1] || "").toLowerCase();
const CATEGORIES_ONLY = flags.has("--categories-only");
const DRY_RUN = flags.has("--dry-run");

if (!FROM || !TO) {
  console.error(
    "Usage: node scripts/copy-tenant-config.js <fromSlug> <toSlug> [--categories-only] [--dry-run]"
  );
  process.exit(1);
}
if (FROM === TO) {
  console.error("Source and target must differ.");
  process.exit(1);
}

async function main() {
  console.log(
    `Copying ${CATEGORIES_ONLY ? "categories" : "master config"}: ${FROM} → ${TO}` +
    (DRY_RUN ? "  [DRY RUN — nothing will be written]" : "")
  );

  // Show what's there before touching anything.
  const preview = await pool.query(
    `SELECT name, gl_account, normalized, requires_bill, enabled
       FROM expense_categories WHERE slug = $1 ORDER BY name`,
    [FROM],
  );
  const existing = await pool.query(
    `SELECT COUNT(*)::int AS n FROM expense_categories WHERE slug = $1`,
    [TO],
  );
  console.log(`  source has ${preview.rows.length} categories; target currently has ${existing.rows[0].n}`);
  for (const r of preview.rows) {
    console.log(`    · ${r.name}  GL=${r.gl_account || "-"}  bill=${r.requires_bill}  enabled=${r.enabled}`);
  }

  if (DRY_RUN) {
    console.log("\nDry run — no changes made.");
    await pool.end();
    return;
  }

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

  if (CATEGORIES_ONLY) {
    console.log("  rules / policy caps: skipped (--categories-only)");
    console.log("Done.");
    await pool.end();
    return;
  }

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
