// Bootstrap the `employees` table from the master spreadsheet and set every
// row's password to bcrypt("Demo@123"). Idempotent — safe to re-run.
//
// Steps:
//   1. CREATE TABLE IF NOT EXISTS employees(...) with `email` as the primary key.
//   2. INSERT ... ON CONFLICT (email) DO NOTHING for each seed row.
//   3. UPDATE password_hash for every row whose hash is still NULL.
//
// Run:    npm run seed:passwords

require("dotenv").config();
const bcrypt = require("bcryptjs");
const pool = require("../dbClient");

const DEMO_PASSWORD = "Demo@123";

// Columns: email, name, grade, manager_email, employee_id, department,
//          company_code, vendor_code, cost_center, section_code, finance_manager_email,
//          role, tenant
//
// Super-admin convention: role='super_admin', tenant=NULL. The dashboard treats
// a NULL tenant as platform-wide.
const FINANCE_MANAGER = "kabir.singh@xeltrion.com";
const TENANT = "xeltrion";
const SEED_ROWS = [
  // ─── Platform owner (super-admin, no tenant) ─────────────────────────────
  ["info@cgbindia.com",          "CGB Platform Admin", null, null,                          "CGB-0001", "Platform",    null,    null,    null,    null,    null,             "super_admin", null],

  // ─── Xeltrion tenant ──────────────────────────────────────────────────────
  ["aarav.sharma@xeltrion.com",  "Aarav Sharma",   "G5", "riya.mehra@xeltrion.com",     "EMP1001", "Engineering", "XEL01", "VND201", "CC101", "SC01", FINANCE_MANAGER, "employee", TENANT],
  ["riya.mehra@xeltrion.com",    "Riya Mehra",     "G7", "kabir.singh@xeltrion.com",    "EMP1002", "Engineering", "XEL01", "VND201", "CC100", "SC00", FINANCE_MANAGER, "employee", TENANT],
  ["kabir.singh@xeltrion.com",   "Kabir Singh",    "G8", "anaya.khanna@xeltrion.com",   "EMP1003", "Management",  "XEL01", "VND000", "CC000", "SC00", FINANCE_MANAGER, "employee", TENANT],
  ["anaya.khanna@xeltrion.com",  "Anaya Khanna",   "G9", "board.office@xeltrion.com",   "EMP1004", "Executive",   "XEL01", "VND000", "CC000", "SC00", FINANCE_MANAGER, "employee", TENANT],
  ["vihaan.gupta@xeltrion.com",  "Vihaan Gupta",   "G4", "aarav.sharma@xeltrion.com",   "EMP1005", "QA",          "XEL01", "VND202", "CC102", "SC02", FINANCE_MANAGER, "employee", TENANT],
  ["siya.verma@xeltrion.com",    "Siya Verma",     "G3", "vihaan.gupta@xeltrion.com",   "EMP1006", "Support",     "XEL01", "VND203", "CC103", "SC03", FINANCE_MANAGER, "employee", TENANT],
  ["aditya.nair@xeltrion.com",   "Aditya Nair",    "G5", "riya.mehra@xeltrion.com",     "EMP1007", "DevOps",      "XEL01", "VND204", "CC104", "SC04", FINANCE_MANAGER, "employee", TENANT],
  ["isha.kapoor@xeltrion.com",   "Isha Kapoor",    "G4", "aditya.nair@xeltrion.com",    "EMP1008", "CloudOps",    "XEL01", "VND204", "CC104", "SC04", FINANCE_MANAGER, "employee", TENANT],
  ["krish.malhotra@xeltrion.com","Krish Malhotra", "G6", "kabir.singh@xeltrion.com",    "EMP1009", "Product",     "XEL01", "VND205", "CC105", "SC05", FINANCE_MANAGER, "employee", TENANT],
  ["meera.joshi@xeltrion.com",   "Meera Joshi",    "G5", "krish.malhotra@xeltrion.com", "EMP1010", "Product",     "XEL01", "VND205", "CC105", "SC05", FINANCE_MANAGER, "admin",    TENANT],
  ["board.office@xeltrion.com",  "Board Office",   "G10", "",                           "EMP1000", "Executive",   "XEL01", "VND000", "CC000", "SC00", FINANCE_MANAGER, "employee", TENANT],
];

async function main() {
  console.log("Creating employees table (if missing)…");
  await pool.query(`
    CREATE TABLE IF NOT EXISTS employees (
      email                  TEXT PRIMARY KEY,
      name                   TEXT NOT NULL,
      grade                  TEXT,
      manager_email          TEXT,
      employee_id            TEXT,
      department             TEXT,
      company_code           TEXT,
      vendor_code            TEXT,
      cost_center            TEXT,
      section_code           TEXT,
      finance_manager_email  TEXT,
      role                   TEXT NOT NULL DEFAULT 'employee',
      tenant                 TEXT NOT NULL DEFAULT 'xeltrion',
      password_hash          TEXT,
      created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  // Ensure columns exist on tables created before these were added.
  await pool.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS password_hash TEXT`);
  await pool.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS finance_manager_email TEXT`);
  await pool.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'employee'`);
  await pool.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS tenant TEXT NOT NULL DEFAULT 'xeltrion'`);
  // Super-admins live outside any tenant — relax the NOT NULL constraint.
  // Idempotent: a no-op once the column is already nullable.
  await pool.query(`ALTER TABLE employees ALTER COLUMN tenant DROP NOT NULL`);

  console.log(`Seeding ${SEED_ROWS.length} rows…`);
  let inserted = 0;
  for (const row of SEED_ROWS) {
    const r = await pool.query(
      `INSERT INTO employees
         (email, name, grade, manager_email, employee_id,
          department, company_code, vendor_code, cost_center, section_code,
          finance_manager_email, role, tenant)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       ON CONFLICT (email) DO UPDATE SET
         finance_manager_email = EXCLUDED.finance_manager_email,
         role                  = EXCLUDED.role,
         tenant                = EXCLUDED.tenant,
         updated_at            = NOW()`,
      row
    );
    inserted += r.rowCount;
  }
  console.log(`Rows inserted/updated: ${inserted}.`);

  console.log(`Hashing demo password "${DEMO_PASSWORD}"…`);
  const passwordHash = await bcrypt.hash(DEMO_PASSWORD, 10);

  const result = await pool.query(
    `UPDATE employees
        SET password_hash = $1,
            updated_at    = now()
      WHERE password_hash IS NULL`,
    [passwordHash]
  );
  console.log(`Password hashes set for ${result.rowCount} rows.`);

  // ──────────────────────────────────────────────────────────────────────────
  // tenant_settings — per-tenant plan/status/MRR. Used by the super-admin
  // overview (MRR KPI, revenue-by-plan chart, plan badges on tenants list).
  // ──────────────────────────────────────────────────────────────────────────
  console.log("Ensuring tenant_settings table…");
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tenant_settings (
      slug         TEXT PRIMARY KEY,
      plan         TEXT NOT NULL DEFAULT 'growth',
      status       TEXT NOT NULL DEFAULT 'active',
      mrr_amount   NUMERIC(10,2) NOT NULL DEFAULT 800,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // Explicit seed of known tenants. Add rows here to control plan + MRR.
  const TENANT_SETTINGS_SEED = [
    // [slug, plan, status, mrr_amount]
    ["xeltrion", "growth", "active", 800],
  ];
  for (const [slug, plan, status, mrr] of TENANT_SETTINGS_SEED) {
    await pool.query(
      `INSERT INTO tenant_settings (slug, plan, status, mrr_amount)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (slug) DO UPDATE SET
         plan       = EXCLUDED.plan,
         status     = EXCLUDED.status,
         mrr_amount = EXCLUDED.mrr_amount,
         updated_at = NOW()`,
      [slug, plan, status, mrr],
    );
  }

  // Auto-create defaults for any tenant present in employees but not yet in
  // tenant_settings. Keeps the two tables in sync as new tenants sign up.
  const autoSeed = await pool.query(`
    INSERT INTO tenant_settings (slug, plan, status, mrr_amount)
    SELECT DISTINCT tenant, 'growth', 'active', 800
      FROM employees
     WHERE tenant IS NOT NULL AND tenant <> ''
       AND NOT EXISTS (SELECT 1 FROM tenant_settings WHERE slug = employees.tenant)
  `);
  console.log(
    `tenant_settings rows: ${TENANT_SETTINGS_SEED.length} explicit + ${autoSeed.rowCount} auto-defaulted.`,
  );

  console.log("Done.");
  await pool.end();
}

main().catch(async (err) => {
  console.error("Seed failed:", err);
  try { await pool.end(); } catch {}
  process.exit(1);
});
