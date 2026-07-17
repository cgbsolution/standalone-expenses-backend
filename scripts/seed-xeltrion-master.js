// Seed the Xeltrion tenant's master config (expense types + GL codes, output/
// policy rules, and grade-wise policy caps) from scripts/xeltrion-master.json,
// which is generated straight from the client's Master.xlsx.
//
// The chatbot is the source of truth that *enforces* these; the dashboard just
// *displays* them. Idempotent — safe to re-run.
//
// Run:  node scripts/seed-xeltrion-master.js  [tenantSlug]

require("dotenv").config();
const fs = require("fs");
const path = require("path");
const pool = require("../dbClient");

const SLUG = process.argv[2] || "xeltrion";
const DATA = JSON.parse(fs.readFileSync(path.join(__dirname, "xeltrion-master.json"), "utf8"));

// Palette so each category gets a stable colour in the dashboard.
const PALETTE = ["#6366F1", "#0EA5E9", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6", "#EC4899", "#64748B", "#14B8A6"];

async function ensureSchema() {
  // Extend expense_categories with the master-sheet attributes.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS expense_categories (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      slug TEXT NOT NULL, name TEXT NOT NULL,
      color TEXT NOT NULL DEFAULT '#6366F1', icon TEXT NOT NULL DEFAULT 'folder',
      monthly_budget NUMERIC NOT NULL DEFAULT 0, gl_account TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
  for (const col of [
    "normalized TEXT",
    "requires_bill BOOLEAN NOT NULL DEFAULT TRUE",
    "excluded_from_auto_approve BOOLEAN NOT NULL DEFAULT FALSE",
    "enabled BOOLEAN NOT NULL DEFAULT TRUE",
    "gl_project TEXT NOT NULL DEFAULT ''",
    "gl_crm TEXT NOT NULL DEFAULT ''",
  ]) {
    await pool.query(`ALTER TABLE expense_categories ADD COLUMN IF NOT EXISTS ${col}`);
  }
  // Dedupe a category by (slug, name) so re-runs update in place.
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS uq_categories_slug_name ON expense_categories (slug, name)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tenant_rules (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      slug TEXT NOT NULL, rule_id TEXT NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT TRUE, priority INT NOT NULL DEFAULT 0,
      rule_group TEXT NOT NULL DEFAULT '', rule_type TEXT NOT NULL DEFAULT '',
      params JSONB NOT NULL DEFAULT '{}'::jsonb,
      UNIQUE (slug, rule_id)
    )`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tenant_policy_caps (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      slug TEXT NOT NULL, normalized TEXT NOT NULL, grade TEXT NOT NULL,
      cap_amount NUMERIC NOT NULL DEFAULT 0,
      is_actuals BOOLEAN NOT NULL DEFAULT FALSE, self_approve BOOLEAN NOT NULL DEFAULT TRUE,
      UNIQUE (slug, normalized, grade)
    )`);
}

async function main() {
  console.log(`Seeding master config for tenant "${SLUG}"…`);
  await ensureSchema();

  let i = 0;
  for (const c of DATA.categories) {
    await pool.query(
      `INSERT INTO expense_categories
         (slug, name, color, icon, gl_account, normalized, requires_bill, excluded_from_auto_approve, enabled, gl_project, gl_crm)
       VALUES ($1,$2,$3,'folder',$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT (slug, name) DO UPDATE SET
         gl_account = EXCLUDED.gl_account, normalized = EXCLUDED.normalized,
         requires_bill = EXCLUDED.requires_bill,
         excluded_from_auto_approve = EXCLUDED.excluded_from_auto_approve,
         enabled = EXCLUDED.enabled, gl_project = EXCLUDED.gl_project, gl_crm = EXCLUDED.gl_crm`,
      [SLUG, c.name, PALETTE[i++ % PALETTE.length], c.glCorporate, c.normalized,
       c.requiresBill, c.excludedFromAutoApprove, c.enabled, c.glProject, c.glCrm],
    );
  }
  console.log(`  categories: ${DATA.categories.length}`);

  for (const r of DATA.rules) {
    await pool.query(
      `INSERT INTO tenant_rules (slug, rule_id, enabled, priority, rule_group, rule_type, params)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (slug, rule_id) DO UPDATE SET
         enabled = EXCLUDED.enabled, priority = EXCLUDED.priority,
         rule_group = EXCLUDED.rule_group, rule_type = EXCLUDED.rule_type, params = EXCLUDED.params`,
      [SLUG, r.ruleId, r.enabled, r.priority, r.ruleGroup, r.ruleType, JSON.stringify(r.params)],
    );
  }
  console.log(`  rules: ${DATA.rules.length}`);

  for (const p of DATA.policyCaps) {
    await pool.query(
      `INSERT INTO tenant_policy_caps (slug, normalized, grade, cap_amount, is_actuals, self_approve)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (slug, normalized, grade) DO UPDATE SET
         cap_amount = EXCLUDED.cap_amount, is_actuals = EXCLUDED.is_actuals, self_approve = EXCLUDED.self_approve`,
      [SLUG, p.normalized, p.grade, p.capAmount, p.isActuals, p.selfApprove],
    );
  }
  console.log(`  policy caps: ${DATA.policyCaps.length}`);

  console.log("Done.");
  await pool.end();
}

main().catch(async (e) => {
  console.error("Seed failed:", e.message);
  try { await pool.end(); } catch {}
  process.exit(1);
});
