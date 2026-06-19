// Minimal {{var.path}} template renderer. Keeps templates as plain HTML files.
// Why plain replace instead of Handlebars/EJS: zero deps, easy to read, fine for the
// few transactional templates this app needs. Swap to a real engine when copy gets complex.

const fs = require("fs");
const path = require("path");

const TEMPLATES_DIR = path.join(__dirname, "templates");

function getByPath(obj, dottedPath) {
  return dottedPath.split(".").reduce((acc, k) => (acc == null ? acc : acc[k]), obj);
}

function escapeHtml(value) {
  if (value == null) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Maps event types to template files + subject line builders.
const EVENT_REGISTRY = {
  "expense.submitted": {
    template: "expense_submitted.html",
    subject: (ctx) =>
      `New expense awaiting your approval — ${ctx.expense?.ExpenseTitle || "Expense"} (₹${ctx.expense?.TotalAmount ?? "?"})`,
  },
  "expense.resubmitted": {
    template: "expense_resubmitted.html",
    subject: (ctx) =>
      `Resubmitted: ${ctx.expense?.ExpenseTitle || "Expense"} — please re-review`,
  },
  "expense.approved": {
    template: "expense_approved.html",
    subject: (ctx) => `Your expense was approved — ${ctx.expense?.ExpenseTitle || "Expense"}`,
  },
  "expense.rejected": {
    template: "expense_rejected.html",
    subject: (ctx) => `Your expense was rejected — ${ctx.expense?.ExpenseTitle || "Expense"}`,
  },
  "expense.sap_status_changed": {
    template: "expense_sap_status.html",
    subject: (ctx) => `Expense status update from SAP — ${ctx.newStatus || ""}`,
  },
  "account.invite": {
    template: "account_password.html",
    subject: (ctx) => `You're invited to ${ctx.tenantName || "ExpGenie"} — set your password`,
  },
  "account.reset": {
    template: "account_password.html",
    subject: () => "Reset your ExpGenie password",
  },
};

function render(eventType, ctx) {
  const entry = EVENT_REGISTRY[eventType];
  if (!entry) throw new Error(`Unknown event type: ${eventType}`);

  const templatePath = path.join(TEMPLATES_DIR, entry.template);
  if (!fs.existsSync(templatePath)) {
    throw new Error(`Template missing: ${templatePath}`);
  }
  const raw = fs.readFileSync(templatePath, "utf8");

  const html = raw.replace(/\{\{\s*([\w.]+)\s*\}\}/g, (_, key) => escapeHtml(getByPath(ctx, key)));
  const subject = entry.subject(ctx);
  return { subject, html };
}

module.exports = { render };
