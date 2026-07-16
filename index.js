const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const swaggerJsDoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ limit: "25mb", extended: true }));

const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Expense Tracker API",
      version: "1.0.0",
      description: "API to manage expenses (Master Expenses, Invoices, etc.)",
    },
    servers: [
      {
        url: process.env.BASE_URL || `http://localhost:${process.env.PORT || 5000}`,
      },
    ],
  },
  apis: ["./routes/*.js"],
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocs));

const masterExpenseRoute = require("./routes/masterExpense");
app.use("/master-expense", masterExpenseRoute);

const authRoute = require("./routes/auth");
app.use("/auth", authRoute);

const usersRoute = require("./routes/users");
app.use("/users", usersRoute);

const tenantsRoute = require("./routes/tenants");
app.use("/tenants", tenantsRoute);

const adminRoute = require("./routes/admin");
app.use("/admin", adminRoute);

const storageRoute = require("./routes/storage");
app.use("/storage", storageRoute);

const notificationsRoute = require("./routes/notifications");
app.use("/notifications", notificationsRoute);

const integrationsRoute = require("./routes/integrations");
app.use("/integrations", integrationsRoute);

app.use("/categories", require("./routes/categories"));
app.use("/tenant-config", require("./routes/tenantConfig"));
app.use("/rules", require("./routes/rules"));

app.get("/", (req, res) => {
  res.status(200).json({ status: "OK", message: "Expense Tracker API running" });
});

app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error("Server Error:", err.stack);
  res.status(500).json({ error: "Internal Server Error" });
});

// One-time, idempotent schema touch-ups for tables/columns added after the
// initial deploy. Safe to run on every boot; a no-op once applied.
const pool = require("./dbClient");
const { ensurePasswordResetTable } = require("./utils/passwordTokens");
async function ensureSchema() {
  try {
    await pool.query(`ALTER TABLE tenant_settings ADD COLUMN IF NOT EXISTS name TEXT`);
    // Self-service profile fields set from the mobile app / dashboard profile page.
    await pool.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS avatar_url TEXT`);
    await pool.query(`ALTER TABLE employees ADD COLUMN IF NOT EXISTS integration_provider TEXT`);
    await ensurePasswordResetTable();

    // In-app notifications. One row per workflow event (submitted / approved /
    // rejected / resubmitted), addressed to a single recipient email. Written by
    // the notifier at the same points the approval emails fire.
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        recipient_email TEXT NOT NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        expense_id TEXT,
        actor_email TEXT,
        read BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_notifications_recipient
      ON notifications (LOWER(recipient_email), created_at DESC)
    `);

    // Per-tenant integration settings (SAP ERP posting, HRMS employee sync).
    // One row per tenant slug; each provider's config lives in a JSONB blob so
    // fields can evolve without migrations. Secrets are stored here but never
    // returned by the API (see routes/integrations.js).
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tenant_integrations (
        slug TEXT PRIMARY KEY,
        sap JSONB NOT NULL DEFAULT '{}'::jsonb,
        hrms JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    // Expense categories (per tenant) — name, colour/icon, monthly budget, GL map.
    await pool.query(`
      CREATE TABLE IF NOT EXISTS expense_categories (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        slug TEXT NOT NULL,
        name TEXT NOT NULL,
        color TEXT NOT NULL DEFAULT '#6366F1',
        icon TEXT NOT NULL DEFAULT 'folder',
        monthly_budget NUMERIC NOT NULL DEFAULT 0,
        gl_account TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_categories_slug ON expense_categories (slug)`);

    // Workspace / platform configuration (per tenant slug; '__platform__' = global).
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tenant_config (
        slug TEXT PRIMARY KEY,
        config JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    // Approval routing rules (per tenant) — conditions + action, priority-ordered.
    await pool.query(`
      CREATE TABLE IF NOT EXISTS approval_rules (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        slug TEXT NOT NULL,
        name TEXT NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        priority INT NOT NULL DEFAULT 0,
        conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
        action TEXT NOT NULL DEFAULT 'route',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_rules_slug ON approval_rules (slug)`);
  } catch (err) {
    console.error("Schema ensure skipped:", err.message);
  }
}

const PORT = process.env.PORT || 5000;
ensureSchema().finally(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Swagger docs at http://localhost:${PORT}/api-docs`);
  });
  // Catch expenses written straight into the DB (chatbot inserts bypass the
  // API) and fire the notifications those rows never triggered.
  require("./pollers/expenseNotificationsPoller").start();
});
