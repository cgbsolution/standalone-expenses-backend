// Public notifier API.
// Today: render template + send via the configured provider.
// Later (when wiring routes): add an audit log + dedup so retries/duplicate
// SAP polls can't email twice. The interface below stays the same.

const { render } = require("./render");

// One-time diagnostic line at module load — visible in the log stream so we
// can confirm the deployed code can read the env vars.
console.log(
  `📧 notifier loaded | provider=${process.env.NOTIFY_PROVIDER || "(unset)"} ` +
  `enabled=${process.env.NOTIFY_ENABLED || "(unset)"} ` +
  `smtp_host=${process.env.SMTP_HOST || "(unset)"} ` +
  `smtp_user=${process.env.SMTP_USER || "(unset)"} ` +
  `smtp_from=${process.env.SMTP_FROM || "(unset)"}`
);

// Pick provider from env. Default = smtp.
//   NOTIFY_PROVIDER=smtp   → notifier/provider/smtp.js
function getProvider() {
  const name = (process.env.NOTIFY_PROVIDER || "smtp").toLowerCase();
  if (name === "smtp") return require("./provider/smtp");
  if (name === "graph") {
    throw new Error("NOTIFY_PROVIDER=graph is no longer supported. Use smtp.");
  }
  throw new Error(`Unknown NOTIFY_PROVIDER: ${name}`);
}

// Pulls submitter info from the existing /employee-info endpoint so templates
// can render real names (e.g. "Tushar Ganatra") instead of raw emails.
// Always fills ctx.employee with at least { FullName: <fallback> }.
const EMPLOYEE_INFO_URL =
  process.env.EMPLOYEE_INFO_URL ||
  "https://ocr-validations-hnh3e7g2bkhhf6hq.southeastasia-01.azurewebsites.net/employee-info";

// Some expense docs (especially those written by the chatbot's expenseagent-dev
// backend) don't carry a top-level TotalAmount. Compute it from the line items
// so the templates always have a number to print.
function ensureTotalAmount(expense) {
  if (!expense) return;
  if (expense.TotalAmount !== undefined && expense.TotalAmount !== null && expense.TotalAmount !== "") {
    // Already set — just normalize formatting (Indian-locale, 2 decimals).
    const n = Number(expense.TotalAmount);
    if (!Number.isNaN(n)) {
      expense.TotalAmount = n.toLocaleString("en-IN", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    }
    return;
  }

  const items = Array.isArray(expense.ExpenseData) ? expense.ExpenseData : [];
  let total = 0;
  for (const item of items) {
    const inv = Number(item?.InvoiceAmount);
    const claim = Number(item?.ItemData?.ClaimAmount);
    if (!Number.isNaN(inv) && inv > 0) total += inv;
    else if (!Number.isNaN(claim) && claim > 0) total += claim;
  }
  expense.TotalAmount = total > 0
    ? total.toLocaleString("en-IN", { minimumFractionDigits: 2, maximumFractionDigits: 2 })
    : "0.00";
}

// Convert ISO timestamps to a friendly "DD-MM-YYYY HH:MM" form.
// Mutates fields in place; safe because the route handler has already returned
// before safeNotify runs (setImmediate fires after res.json).
function formatNiceDate(value) {
  if (!value) return value;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const dd = String(d.getDate()).padStart(2, "0");
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const yyyy = d.getFullYear();
  const HH = String(d.getHours()).padStart(2, "0");
  const MM = String(d.getMinutes()).padStart(2, "0");
  return `${dd}-${mm}-${yyyy} ${HH}:${MM}`;
}

function formatExpenseDates(expense) {
  if (!expense) return;
  if (expense.SubmissionDate) expense.SubmissionDate = formatNiceDate(expense.SubmissionDate);
  if (expense.ApprovedAt) expense.ApprovedAt = formatNiceDate(expense.ApprovedAt);
  if (expense.LastActionAt) expense.LastActionAt = formatNiceDate(expense.LastActionAt);
  if (expense.RejectionInfo && expense.RejectionInfo.RejectedAt) {
    expense.RejectionInfo.RejectedAt = formatNiceDate(expense.RejectionInfo.RejectedAt);
  }
}

// Fall back to ApprovalHistory[0].at when chatbot doesn't set SubmissionDate.
function ensureSubmissionDate(expense) {
  if (!expense) return;
  if (expense.SubmissionDate) return;
  const first = Array.isArray(expense.ApprovalHistory) ? expense.ApprovalHistory[0] : null;
  if (first?.at) expense.SubmissionDate = first.at;
}

async function fetchEmployeeInfo(email) {
  if (!email) return {};
  try {
    const url = `${EMPLOYEE_INFO_URL}?emp_email=${encodeURIComponent(email)}`;
    const resp = await fetch(url);
    if (resp.ok) return await resp.json();
  } catch (err) {
    console.warn(`employee-info fetch failed for ${email}:`, err.message);
  }
  return {};
}

function fallbackName(email) {
  return email ? email.split("@")[0] : "";
}

async function enrichCtx(ctx) {
  // Always normalize, even on second call.
  ensureTotalAmount(ctx.expense);
  ensureSubmissionDate(ctx.expense);
  formatExpenseDates(ctx.expense);

  // ---- Submitter (employee) lookup ----
  if (!ctx.employee) {
    const submitterEmail = ctx.expense?.SubmitterEmail || ctx.expense?.submitterEmail || "";
    const employee = await fetchEmployeeInfo(submitterEmail);
    if (!employee.FullName) employee.FullName = fallbackName(submitterEmail) || "Submitter";
    ctx.employee = employee;
  }

  // ---- Approver lookup ----
  // For submission-style events the recipient IS the approver, so we can use it.
  // For approved/rejected the approver is on the expense doc.
  if (!ctx.approver) {
    const approverEmail =
      ctx.expense?.ApproverEmail ||
      (/(submitted|resubmitted)$/.test(ctx._eventType || "") ? ctx.recipient : "") ||
      "";
    const approver = await fetchEmployeeInfo(approverEmail);
    if (!approver.FullName) approver.FullName = fallbackName(approverEmail) || "Manager";
    ctx.approver = approver;
  }

  return ctx;
}

async function notify(eventType, ctx) {
  if (!ctx || !ctx.recipient) {
    throw new Error("notify() requires ctx.recipient");
  }

  ctx._eventType = eventType; // used by enrichCtx for approver fallback
  await enrichCtx(ctx);

  const { subject, html } = render(eventType, ctx);
  const provider = getProvider();
  const result = await provider.send({ to: ctx.recipient, subject, html });
  return { eventType, recipient: ctx.recipient, ...result };
}

// Fire-and-forget wrapper used by HTTP route handlers.
// - Respects NOTIFY_ENABLED feature flag (no-op when "false" or unset).
// - Logs and swallows errors; the API response must never wait on or fail
//   because of email delivery.
async function safeNotify(eventType, ctx) {
  // Log entry unconditionally — proves the route is calling us.
  console.log(`📧 safeNotify(${eventType}) called | recipient=${ctx?.recipient || "(none)"} | enabled=${process.env.NOTIFY_ENABLED}`);

  if (process.env.NOTIFY_ENABLED !== "true") {
    console.log(`📧 safeNotify(${eventType}) skipped: NOTIFY_ENABLED is "${process.env.NOTIFY_ENABLED}", expected literal "true"`);
    return;
  }
  if (!ctx || !ctx.recipient) {
    console.warn(`📧 safeNotify(${eventType}) skipped: no recipient`);
    return;
  }
  try {
    const result = await notify(eventType, ctx);
    console.log(`📧 sent ${eventType} → ${ctx.recipient}`, result.providerMessageId || "");
  } catch (err) {
    console.error(`📧 ${eventType} failed:`, err.message);
    if (err.stack) console.error(err.stack);
  }
}

// Maps a status transition to the right event + recipient.
// Resubmission = something that was Rejected/Draft going back to Pending.
// Returns null if the transition shouldn't trigger an email.
function pickEventForStatusChange(oldStatus, newStatus, resource) {
  if (newStatus === "Approved" && oldStatus !== "Approved") {
    return {
      type: "expense.approved",
      ctx: { expense: resource, recipient: resource.SubmitterEmail },
    };
  }
  if (newStatus === "Rejected" && oldStatus !== "Rejected") {
    const reason = resource.RejectionInfo?.Reason || "";
    const rawComments = resource.RejectionInfo?.Comments || "";
    // Hide the auto-generated "Rejected by <email>. <reason>" string when the
    // user didn't actually type anything in the rejection modal.
    const isBoilerplate = /^Rejected by\s+\S+\.\s/.test(rawComments);
    const comments = isBoilerplate || !rawComments ? "—" : rawComments;
    return {
      type: "expense.rejected",
      ctx: {
        expense: resource,
        recipient: resource.SubmitterEmail,
        reason,
        comments,
      },
    };
  }
  if (
    newStatus === "Pending" &&
    (oldStatus === "Rejected" || oldStatus === "Draft")
  ) {
    return {
      type: "expense.resubmitted",
      ctx: { expense: resource, recipient: resource.ApproverEmail },
    };
  }
  return null;
}

module.exports = { notify, safeNotify, pickEventForStatusChange };
