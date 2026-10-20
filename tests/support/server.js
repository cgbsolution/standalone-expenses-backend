// A throwaway database and a real API process for end-to-end tests.
//
// TEST_DATABASE_URL must name a Postgres database whose name contains "test":
// its public schema is dropped and rebuilt. Unset, the database tests skip, so
// `npm test` still works anywhere (the deploy pipeline runs it with no DB).
//
// The API runs as a child process from the OS temp directory, so a developer's
// .env (live database, SMTP, Supabase keys) is never loaded.

const os = require("os");
const net = require("net");
const path = require("path");
const { spawn } = require("child_process");
const { Client } = require("pg");
const bcrypt = require("bcryptjs");

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL || "";
const SKIP = TEST_DATABASE_URL
  ? false
  : "set TEST_DATABASE_URL to a throwaway Postgres whose name contains 'test'";
const PASSWORD = "Passw0rd!";
const JWT_SECRET = "test-secret-0123456789-0123456789-abcdef";

function guard(url) {
  const name = new URL(url).pathname.replace(/^\//, "");
  if (!/test/i.test(name)) {
    throw new Error(`TEST_DATABASE_URL must name a database containing "test" (got "${name}")`);
  }
  return url;
}

/** Empty the test database and create the tables the API expects to exist already. */
async function resetDatabase() {
  const db = new Client({ connectionString: guard(TEST_DATABASE_URL) });
  await db.connect();
  await db.query(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`);
  // Created outside the API in production (Supabase); index.js adds the rest.
  await db.query(`
    CREATE TABLE employees (
      email TEXT PRIMARY KEY, name TEXT NOT NULL, grade TEXT, manager_email TEXT, employee_id TEXT,
      department TEXT, company_code TEXT, vendor_code TEXT, cost_center TEXT, section_code TEXT,
      finance_manager_email TEXT, role TEXT NOT NULL DEFAULT 'employee', tenant TEXT,
      password_hash TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
    CREATE TABLE expenses (
      id TEXT PRIMARY KEY, user_id TEXT, unique_key TEXT, approver_email TEXT, submitter_email TEXT,
      submitter_name TEXT, approval_status TEXT, data JSONB NOT NULL DEFAULT '{}',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
    CREATE TABLE tenant_settings (
      slug TEXT PRIMARY KEY, name TEXT, plan TEXT, status TEXT, mrr_amount NUMERIC DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now());
  `);
  return db;
}

/** Insert employees: [email, name, role, tenant, managerEmail?, financeManagerEmail?]. */
async function seedPeople(db, people) {
  const hash = await bcrypt.hash(PASSWORD, 4);
  for (const [email, name, role, tenant, manager = null, finance = null] of people) {
    await db.query(
      `INSERT INTO employees (email, name, role, tenant, manager_email, finance_manager_email, password_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [email, name, role, tenant, manager, finance, hash],
    );
  }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

/** Start the API (index.js) against the test database. Resolves once it answers. */
async function startApi(extraEnv = {}) {
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(__dirname, "..", "..", "index.js")], {
    cwd: os.tmpdir(),
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      PORT: String(port),
      DATABASE_URL: TEST_DATABASE_URL,
      PGSSLMODE: "disable",
      AUTH_JWT_SECRET: JWT_SECRET,
      AUTH_ENFORCEMENT: "on",
      NOTIFY_ENABLED: "false",
      // Signing a receipt fails fast here instead of reaching real storage.
      SUPABASE_URL: "http://127.0.0.1:9",
      SUPABASE_SERVICE_ROLE_KEY: "test",
      CORS_ORIGINS: "http://localhost:3000",
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  child.stdout.on("data", (d) => (log += d));
  child.stderr.on("data", (d) => (log += d));
  const base = `http://127.0.0.1:${port}`;
  const started = Date.now();
  for (;;) {
    try {
      if ((await fetch(`${base}/`)).ok) break;
    } catch {}
    if (child.exitCode !== null || Date.now() - started > 30000) {
      child.kill();
      throw new Error(`API did not start:\n${log}`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return {
    base,
    log: () => log,
    stop: () =>
      new Promise((resolve) => {
        if (child.exitCode !== null) return resolve();
        child.once("exit", resolve);
        child.kill();
      }),
    call: async (method, url, { token, body, headers = {} } = {}) => {
      const response = await fetch(base + url, {
        method,
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...headers,
        },
        body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
      });
      let data = null;
      try {
        data = await response.json();
      } catch {}
      return { status: response.status, data, headers: response.headers };
    },
  };
}

async function signIn(api, email, password = PASSWORD) {
  const response = await api.call("POST", "/auth/login", { body: { email, password } });
  if (response.status !== 200) throw new Error(`sign-in for ${email}: ${response.status} ${JSON.stringify(response.data)}`);
  return response.data.token;
}

module.exports = { SKIP, PASSWORD, JWT_SECRET, resetDatabase, seedPeople, startApi, signIn };
