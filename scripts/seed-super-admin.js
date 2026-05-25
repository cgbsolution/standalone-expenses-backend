// Inserts (or upgrades) the platform super-admin into the employees table.
//
// Why: super-admin is just an `employees` row with role='super_admin' and a
// NULL tenant. Hardcoding the identity in code would split the source of truth.
// This script is idempotent — safe to re-run; it never overwrites a hash you
// already changed (unless you pass --reset-password).
//
// Run:  npm run seed:super-admin
//       npm run seed:super-admin -- --reset-password

require("dotenv").config();
const bcrypt = require("bcryptjs");
const pool = require("../dbClient");

const SUPER_ADMIN_EMAIL = "info@cgbindia.com";
const SUPER_ADMIN_NAME = "CGB Platform Admin";
const DEFAULT_PASSWORD = "Demo@123";

async function main() {
  const resetPassword = process.argv.includes("--reset-password");
  const passwordHash = await bcrypt.hash(DEFAULT_PASSWORD, 10);

  // Make sure the tenant column can be NULL. seed-passwords does this too;
  // running it here means this script also works on a fresh DB.
  await pool.query(`ALTER TABLE employees ALTER COLUMN tenant DROP NOT NULL`).catch(() => {});

  const { rows: existing } = await pool.query(
    `SELECT email, role, password_hash IS NOT NULL AS has_password
       FROM employees
      WHERE LOWER(email) = LOWER($1)`,
    [SUPER_ADMIN_EMAIL],
  );

  if (existing.length === 0) {
    await pool.query(
      `INSERT INTO employees
         (email, name, grade, manager_email, employee_id,
          department, company_code, vendor_code, cost_center, section_code,
          finance_manager_email, role, tenant, password_hash)
       VALUES ($1, $2, NULL, NULL, 'CGB-0001',
               'Platform', NULL, NULL, NULL, NULL,
               NULL, 'super_admin', NULL, $3)`,
      [SUPER_ADMIN_EMAIL, SUPER_ADMIN_NAME, passwordHash],
    );
    console.log(`Created super-admin row for ${SUPER_ADMIN_EMAIL}`);
    console.log(`  Password set to "${DEFAULT_PASSWORD}" — change it after first login.`);
  } else {
    const row = existing[0];
    const updatePassword = resetPassword || !row.has_password;
    if (updatePassword) {
      await pool.query(
        `UPDATE employees
            SET role          = 'super_admin',
                tenant        = NULL,
                password_hash = $2,
                updated_at    = NOW()
          WHERE LOWER(email) = LOWER($1)`,
        [SUPER_ADMIN_EMAIL, passwordHash],
      );
      console.log(
        `Upgraded ${SUPER_ADMIN_EMAIL} → role=super_admin, tenant=NULL${
          resetPassword ? " (password reset)" : " (password was missing, set to default)"
        }`,
      );
    } else {
      await pool.query(
        `UPDATE employees
            SET role       = 'super_admin',
                tenant     = NULL,
                updated_at = NOW()
          WHERE LOWER(email) = LOWER($1)`,
        [SUPER_ADMIN_EMAIL],
      );
      console.log(`Upgraded ${SUPER_ADMIN_EMAIL} → role=super_admin, tenant=NULL (password kept)`);
    }
  }

  await pool.end();
}

main().catch(async (err) => {
  console.error("Seed failed:", err);
  try { await pool.end(); } catch {}
  process.exit(1);
});
