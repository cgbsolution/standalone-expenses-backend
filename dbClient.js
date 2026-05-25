// Supabase Postgres pool. Single shared instance for the whole process.
// DATABASE_URL is the Supabase connection string. Use the direct host
// `db.<project-ref>.supabase.co:5432` for a single Node process; for serverless
// deployments, swap to the pooler host `aws-0-<region>.pooler.supabase.com:6543`.

const { Pool } = require("pg");
require("dotenv").config();

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL is not set. Required: Supabase Postgres connection string."
  );
}

if (process.env.DATABASE_URL.includes("REPLACE_WITH_DB_PASSWORD")) {
  throw new Error(
    "DATABASE_URL still has the REPLACE_WITH_DB_PASSWORD placeholder. " +
      "Set the real Supabase database password in .env."
  );
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

pool.on("error", (err) => {
  console.error("Postgres idle client error:", err.message);
});

module.exports = pool;
