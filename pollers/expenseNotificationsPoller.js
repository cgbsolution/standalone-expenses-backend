// Expenses written straight into the DB (the chatbot inserts rows itself,
// bypassing POST /master-expense) never trigger the notification pipeline.
// This poller sweeps for Pending expenses whose CURRENT approver has no
// "approval needed" notification yet and fires the standard pipeline for
// them (in-app row + email). Idempotent via the NOT EXISTS dedupe.

const pool = require("../dbClient");
const { safeNotify } = require("../notifier");

// Mirror of masterExpense.js rowToShape — keep in sync with the expenses schema.
function rowToShape(row) {
  return {
    id: row.id,
    ...row.data,
    ApproverEmail: row.approver_email,
    SubmitterEmail: row.submitter_email,
    SubmitterName: row.submitter_name,
    ApprovalStatus: row.approval_status,
    ExpenseId: row.unique_key,
    SubmissionDate: row.data?.SubmissionDate || row.created_at,
  };
}

async function sweepOnce() {
  const { rows } = await pool.query(`
    SELECT * FROM expenses e
     WHERE e.approval_status ILIKE 'Pending%'
       AND e.approver_email IS NOT NULL AND e.approver_email <> ''
       AND e.created_at > NOW() - INTERVAL '48 hours'
       AND e.created_at < NOW() - INTERVAL '30 seconds'
       AND NOT EXISTS (
         SELECT 1 FROM notifications n
          WHERE n.expense_id = e.id
            AND n.type = 'approval_needed'
            AND LOWER(n.recipient_email) = LOWER(e.approver_email)
       )
     ORDER BY e.created_at ASC
     LIMIT 20
  `);

  for (const row of rows) {
    console.log(`🔁 poller: notifying ${row.approver_email} about expense ${row.id}`);
    await safeNotify("expense.submitted", {
      expense: rowToShape(row),
      recipient: row.approver_email,
    });
  }
  return rows.length;
}

let timer = null;
let running = false;

function start(intervalMs = 60_000) {
  if (timer) return;
  const tick = async () => {
    if (running) return; // never overlap sweeps
    running = true;
    try {
      await sweepOnce();
    } catch (e) {
      console.error("🔁 notifications poller failed:", e.message);
    } finally {
      running = false;
    }
  };
  timer = setInterval(tick, intervalMs);
  if (timer.unref) timer.unref();
  const first = setTimeout(tick, 5_000); // first sweep shortly after boot
  if (first.unref) first.unref();
  console.log(`🔁 expense notifications poller started (every ${Math.round(intervalMs / 1000)}s)`);
}

module.exports = { start, sweepOnce };
