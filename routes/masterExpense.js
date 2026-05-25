const express = require("express");
const { v4: uuidv4 } = require("uuid");
const pool = require("../dbClient");
const { safeNotify, pickEventForStatusChange } = require("../notifier");

const router = express.Router();

// Fields that live in flat columns. Anything else in the incoming JSON gets
// stuffed into the `data` JSONB column. Keep this list in sync with the
// expenses schema (id, user_id, unique_key, approver_email, submitter_email,
// submitter_name, approval_status, created_at, updated_at, data).
const FLAT_FIELDS = new Set([
  "id",
  "ApproverEmail",
  "SubmitterEmail",
  "SubmitterName",
  "ApprovalStatus",
  "ExpenseId",
]);

function enrichInvoice(inv) {
  return {
    ...inv,
    EMSUniqueId: inv.EMSUniqueId || uuidv4(),
    PostingDate: inv.PostingDate || new Date().toISOString().split("T")[0],
    DocumentDate: inv.DocumentDate || new Date().toISOString().split("T")[0],
    SelfApprove: inv.SelfApprove || false,
  };
}

function splitForInsert(payload, id) {
  const flat = {
    id,
    user_id: payload.SubmitterEmail || "",
    unique_key: payload.ExpenseId || id,
    approver_email: payload.ApproverEmail || null,
    submitter_email: payload.SubmitterEmail || null,
    submitter_name: payload.SubmitterName || "",
    approval_status: payload.ApprovalStatus || "Pending",
  };

  const data = {};
  for (const [k, v] of Object.entries(payload)) {
    if (FLAT_FIELDS.has(k)) continue;
    data[k] = v;
  }
  return { flat, data };
}

// Reconstruct the API response shape clients expect (top-level camelCase fields).
function rowToShape(row) {
  if (!row) return null;
  return {
    id: row.id,
    ...row.data,
    ApproverEmail: row.approver_email,
    SubmitterEmail: row.submitter_email,
    SubmitterName: row.submitter_name,
    ApprovalStatus: row.approval_status,
    ExpenseId: row.unique_key,
    SubmissionDate: row.data?.SubmissionDate || row.created_at,
    _ts: Math.floor(new Date(row.updated_at || row.created_at).getTime() / 1000),
  };
}

/**
 * @swagger
 * tags:
 *   name: MasterExpense
 *   description: APIs for managing master expenses
 */

/**
 * @swagger
 * /master-expense:
 *   post:
 *     summary: Submit a new master expense with invoices
 *     tags: [MasterExpense]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - ExpenseTitle
 *               - ApproverEmail
 *               - SubmitterEmail
 *               - ApprovalStatus
 *               - ExpenseData
 *             properties:
 *               ExpenseTitle: { type: string }
 *               ExpenseId: { type: string }
 *               ApproverEmail: { type: string }
 *               SubmitterEmail: { type: string }
 *               SubmitterName: { type: string }
 *               ApprovalStatus: { type: string }
 *               ExpenseData:
 *                 type: array
 *                 items: { type: object }
 *     responses:
 *       200: { description: Created }
 *       400: { description: Invalid request payload }
 *       500: { description: Failed to submit master expense }
 */
router.post("/", async (req, res) => {
  try {
    const { ExpenseTitle, ApproverEmail, SubmitterEmail, ApprovalStatus, ExpenseData } = req.body;

    if (!ExpenseTitle || !ApproverEmail || !SubmitterEmail || !ApprovalStatus || !Array.isArray(ExpenseData)) {
      return res.status(400).json({ error: "Invalid request payload" });
    }

    const enrichedData = ExpenseData.map(enrichInvoice);
    const totalAmount = enrichedData.reduce(
      (sum, inv) => sum + (Number(inv.InvoiceAmount) || 0),
      0
    );

    const id = Date.now().toString();
    const submissionDate = new Date().toISOString();

    const enrichedPayload = {
      ...req.body,
      ExpenseData: enrichedData,
      SubmissionDate: submissionDate,
      TotalAmount: totalAmount,
      ApprovalHistory: [
        {
          at: submissionDate,
          by: SubmitterEmail,
          from: "Start",
          to: "Pending",
          comments: "Expense submitted and parked successfully",
        },
      ],
    };

    const { flat, data } = splitForInsert(enrichedPayload, id);

    const { rows } = await pool.query(
      `INSERT INTO expenses
         (id, user_id, unique_key, approver_email, submitter_email, submitter_name,
          approval_status, data, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
       RETURNING *`,
      [
        flat.id,
        flat.user_id,
        flat.unique_key,
        flat.approver_email,
        flat.submitter_email,
        flat.submitter_name,
        flat.approval_status,
        data,
      ]
    );

    const saved = rowToShape(rows[0]);
    console.log(`POST /master-expense saved id=${saved.id} from=${SubmitterEmail} approver=${ApproverEmail}`);

    setImmediate(() =>
      safeNotify("expense.submitted", {
        expense: saved,
        recipient: saved.ApproverEmail,
      })
    );

    return res.status(200).json(saved);
  } catch (error) {
    console.error("Error submitting master expense:", error);
    return res.status(500).json({ error: "Failed to submit master expense." });
  }
});

/**
 * @swagger
 * /master-expense:
 *   get:
 *     summary: Get master expenses by submitter email
 *     tags: [MasterExpense]
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema: { type: string }
 *       - in: query
 *         name: approvalStatus
 *         schema: { type: string, example: "Approved, Draft, Pending, All" }
 *     responses:
 *       200: { description: List of master expenses }
 *       400: { description: Email is required }
 *       500: { description: Failed to fetch expenses }
 */
router.get("/", async (req, res) => {
  const { email, approvalStatus } = req.query;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    let result;
    if (!approvalStatus || approvalStatus === "All") {
      result = await pool.query(
        `SELECT * FROM expenses
         WHERE submitter_email = $1
         ORDER BY created_at DESC`,
        [email]
      );
    } else {
      result = await pool.query(
        `SELECT * FROM expenses
         WHERE submitter_email = $1 AND approval_status = $2
         ORDER BY created_at DESC`,
        [email, approvalStatus]
      );
    }
    return res.json(result.rows.map(rowToShape));
  } catch (error) {
    console.error("Error fetching expenses:", error);
    return res.status(500).json({ error: "Failed to fetch expenses." });
  }
});

/**
 * @swagger
 * /master-expense/approver:
 *   get:
 *     summary: Get master expenses where user is approver
 *     tags: [MasterExpense]
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: List of approver's expenses }
 *       400: { description: Email is required }
 *       500: { description: Failed to fetch expenses }
 */
router.get("/approver", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    const { rows } = await pool.query(
      `SELECT * FROM expenses
       WHERE approver_email = $1
       ORDER BY created_at DESC`,
      [email]
    );
    return res.json(rows.map(rowToShape));
  } catch (error) {
    console.error("Error fetching approver expenses:", error);
    return res.status(500).json({ error: "Failed to fetch expenses." });
  }
});

/**
 * @swagger
 * /master-expense/counts:
 *   get:
 *     summary: Get counts of expenses by status (All, Approved, Rejected, Pending, Draft)
 *     tags: [MasterExpense]
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema: { type: string }
 *       - in: query
 *         name: role
 *         schema: { type: string, enum: [submitter, approver], default: submitter }
 *     responses:
 *       200: { description: Count summary }
 *       400: { description: Email is required }
 *       500: { description: Failed to fetch counts }
 */
router.get("/counts", async (req, res) => {
  const { email, role = "submitter" } = req.query;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    const column = role === "approver" ? "approver_email" : "submitter_email";
    const { rows } = await pool.query(
      `SELECT approval_status AS status, COUNT(*)::int AS count
       FROM expenses
       WHERE ${column} = $1
       GROUP BY approval_status`,
      [email]
    );

    const map = rows.reduce((acc, row) => {
      acc[String(row.status || "")] = Number(row.count) || 0;
      return acc;
    }, {});

    return res.json({
      all: Object.values(map).reduce((s, n) => s + n, 0),
      approved: map["Approved"] || 0,
      rejected: map["Rejected"] || 0,
      pending: map["Pending"] || 0,
      draft: map["Draft"] || 0,
    });
  } catch (error) {
    console.error("Error fetching counts:", error);
    return res.status(500).json({ error: "Failed to fetch counts." });
  }
});

/**
 * @swagger
 * /master-expense/non-self-approve:
 *   get:
 *     summary: Get pending master expenses containing non-self-approved invoices
 *     tags: [MasterExpense]
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: List of expenses }
 *       400: { description: Email is required }
 *       500: { description: Failed to fetch expenses }
 */
router.get("/non-self-approve", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: "Email is required" });

  try {
    const { rows } = await pool.query(
      `SELECT * FROM expenses
       WHERE approver_email = $1
         AND approval_status = 'Pending'
         AND EXISTS (
           SELECT 1 FROM jsonb_array_elements(COALESCE(data->'ExpenseData', '[]'::jsonb)) AS item
           WHERE COALESCE((item->>'SelfApprove')::boolean, false) = false
         )
       ORDER BY created_at DESC`,
      [email]
    );
    return res.json(rows.map(rowToShape));
  } catch (error) {
    console.error("Error fetching non-self-approved expenses:", error);
    return res.status(500).json({ error: "Failed to fetch expenses." });
  }
});

// Look up the submitter's finance manager email from the employees table.
// Returns "" if no row (and logs a warning — finance approval can't proceed
// for an unknown submitter, which is fine: the manager-approval step still works).
async function lookupFinanceManagerEmail(submitterEmail) {
  if (!submitterEmail) return "";
  try {
    const { rows } = await pool.query(
      `SELECT finance_manager_email FROM employees WHERE LOWER(email) = LOWER($1) LIMIT 1`,
      [submitterEmail]
    );
    return rows[0]?.finance_manager_email || "";
  } catch (e) {
    console.warn("lookupFinanceManagerEmail failed:", e.message);
    return "";
  }
}

/*
 * Two-level approval workflow:
 *
 *   submit            → row written with approver_email = submitter.manager_email,
 *                       approval_status = 'Pending'
 *
 *   manager approves  → if submitter.finance_manager_email exists AND differs from
 *                       the current approver, move approver_email to that finance
 *                       manager and KEEP approval_status = 'Pending'. The expense
 *                       now appears in the finance manager's queue.
 *
 *   finance approves  → approval_status = 'Approved'. Final.
 *
 *   reject (any level)→ approval_status = 'Rejected'. Final.
 *
 *   SAP integration is intentionally NOT called — removed by request.
 */
async function updateStatus(id, body) {
  const { ApprovalStatus, UpdatedBy, Comments, RejectionReason } = body || {};
  if (!ApprovalStatus) {
    const err = new Error("ApprovalStatus is required");
    err.status = 400;
    throw err;
  }

  const { rows: existingRows } = await pool.query(
    `SELECT * FROM expenses WHERE id = $1`,
    [id]
  );
  if (!existingRows.length) {
    const err = new Error("Expense not found");
    err.status = 404;
    throw err;
  }

  const existingRow = existingRows[0];
  const oldStatus = existingRow.approval_status || "Pending";
  const submitterEmail = existingRow.submitter_email || "";
  const currentApprover = (existingRow.approver_email || "").toLowerCase();
  const now = new Date().toISOString();

  // Decide the new flat-column state based on the workflow stage.
  let newApprovalStatus = ApprovalStatus;
  let newApproverEmail = existingRow.approver_email; // unchanged by default
  let actionLabel = "Status Update";
  let routeNote = "";

  if (ApprovalStatus === "Approved") {
    const financeManagerEmail = await lookupFinanceManagerEmail(submitterEmail);
    const isFinanceLevel =
      !financeManagerEmail || financeManagerEmail.toLowerCase() === currentApprover;

    if (isFinanceLevel) {
      // Finance manager (or there is none configured): finalise.
      newApprovalStatus = "Approved";
      newApproverEmail = existingRow.approver_email;
      actionLabel = "Approved by Finance";
      routeNote = "Approved by Finance Manager. Expense finalised.";
    } else {
      // Manager approved → forward to finance manager. Stay 'Pending'.
      newApprovalStatus = "Pending";
      newApproverEmail = financeManagerEmail;
      actionLabel = "Forwarded to Finance";
      routeNote = `Approved by Manager. Forwarded to Finance (${financeManagerEmail}).`;
    }
  } else if (ApprovalStatus === "Rejected") {
    actionLabel = "Rejected";
  }

  const historyEntry = {
    at: now,
    by: UpdatedBy || existingRow.approver_email || "Unknown",
    from: oldStatus,
    to: newApprovalStatus,
    comments: Comments || routeNote || actionLabel,
    action_status: actionLabel,
  };

  const newDataPatches = { LastActionAt: now };

  if (ApprovalStatus === "Approved" && newApprovalStatus === "Approved") {
    newDataPatches.ApprovedAt = now;
  }
  if (ApprovalStatus === "Rejected") {
    historyEntry.reason = RejectionReason || "No reason provided";
    if (!Comments) {
      historyEntry.comments = `Rejected by ${historyEntry.by}. ${historyEntry.reason}`;
    }
    newDataPatches.RejectionInfo = {
      Reason: historyEntry.reason,
      Comments: historyEntry.comments,
      RejectedAt: now,
      RejectedBy: historyEntry.by,
    };
  }

  const mergedData = {
    ...existingRow.data,
    ...newDataPatches,
    ApprovalHistory: [
      ...(Array.isArray(existingRow.data?.ApprovalHistory) ? existingRow.data.ApprovalHistory : []),
      historyEntry,
    ],
  };

  const { rows: updatedRows } = await pool.query(
    `UPDATE expenses
       SET approval_status = $1,
           approver_email  = $2,
           data            = $3,
           updated_at      = NOW()
     WHERE id = $4
     RETURNING *`,
    [newApprovalStatus, newApproverEmail, mergedData, id]
  );

  const updated = rowToShape(updatedRows[0]);
  console.log(
    `PUT /master-expense/${id} status ${oldStatus} -> ${newApprovalStatus} ` +
    `approver ${currentApprover || "(none)"} -> ${(newApproverEmail || "").toLowerCase()} ` +
    `by=${UpdatedBy || existingRow.approver_email}`
  );

  // Notifications:
  //   - Manager just approved (forwarding to finance): notify the finance manager
  //     using the "expense.submitted" template (it reads as "new approval request").
  //   - Finance approved (finalised): notify the submitter via "expense.approved".
  //   - Rejected: notify the submitter via "expense.rejected".
  if (ApprovalStatus === "Approved" && newApprovalStatus === "Pending" && newApproverEmail) {
    setImmediate(() =>
      safeNotify("expense.submitted", { expense: updated, recipient: newApproverEmail })
    );
  } else {
    const ev = pickEventForStatusChange(oldStatus, newApprovalStatus, updated);
    if (ev) {
      setImmediate(() => safeNotify(ev.type, ev.ctx));
    }
  }

  return updated;
}

/**
 * @swagger
 * /master-expense/{id}:
 *   put:
 *     summary: Update the status of a master expense
 *     tags: [MasterExpense]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [ApprovalStatus]
 *             properties:
 *               ApprovalStatus: { type: string }
 *     responses:
 *       200: { description: Status updated successfully }
 *       400: { description: ApprovalStatus is required }
 *       404: { description: Expense not found }
 *       500: { description: Failed to update expense }
 */
router.put("/:id", async (req, res) => {
  try {
    const updated = await updateStatus(req.params.id, req.body);
    return res.json(updated);
  } catch (error) {
    const status = error.status || 500;
    if (status === 500) console.error("Error updating status:", error);
    return res.status(status).json({ error: error.message || "Failed to update expense status." });
  }
});

/**
 * @swagger
 * /master-expense/by-id/{id}:
 *   put:
 *     summary: Update ApprovalStatus of a master expense by id (alias of PUT /{id} on Postgres)
 *     tags: [MasterExpense]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [ApprovalStatus]
 *             properties:
 *               ApprovalStatus:
 *                 type: string
 *                 enum: [Approved, Rejected, Pending, Draft]
 *     responses:
 *       200: { description: ApprovalStatus updated }
 *       400: { description: ApprovalStatus is required or invalid }
 *       404: { description: Not found }
 */
router.put("/by-id/:id", async (req, res) => {
  try {
    const updated = await updateStatus(req.params.id, req.body);
    return res.json(updated);
  } catch (error) {
    const status = error.status || 500;
    if (status === 500) console.error("Error updating ApprovalStatus:", error);
    return res.status(status).json({ error: error.message || "Failed to update ApprovalStatus." });
  }
});

/**
 * @swagger
 * /master-expense/notify:
 *   post:
 *     summary: Lightweight notification trigger (no DB write)
 *     description: |
 *       Used by chatbot frontend after the expense has already been saved.
 *       Resolves the recipient automatically when omitted.
 *     tags: [MasterExpense]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [eventType, expense]
 *             properties:
 *               eventType:
 *                 type: string
 *                 enum: [expense.submitted, expense.resubmitted, expense.approved, expense.rejected]
 *               expense: { type: object }
 *               recipient: { type: string }
 *     responses:
 *       200: { description: Notification accepted }
 *       400: { description: Missing fields or no recipient resolvable }
 */
const EMPLOYEE_INFO_URL =
  process.env.EMPLOYEE_INFO_URL ||
  "https://ocr-validations-hnh3e7g2bkhhf6hq.southeastasia-01.azurewebsites.net/employee-info";

async function lookupManagerEmail(submitterEmail) {
  if (!submitterEmail) return "";
  try {
    const url = `${EMPLOYEE_INFO_URL}?emp_email=${encodeURIComponent(submitterEmail)}`;
    const resp = await fetch(url);
    if (!resp.ok) return "";
    const info = await resp.json();
    return info?.ManagerEmail || "";
  } catch (e) {
    console.warn("lookupManagerEmail failed:", e.message);
    return "";
  }
}

router.post("/notify", async (req, res) => {
  try {
    const { eventType, expense, recipient } = req.body || {};
    if (!eventType || !expense) {
      return res.status(400).json({ error: "eventType and expense are required" });
    }

    let to = recipient || "";
    if (!to) {
      if (eventType === "expense.submitted" || eventType === "expense.resubmitted") {
        to = await lookupManagerEmail(expense.SubmitterEmail);
      } else if (eventType === "expense.approved" || eventType === "expense.rejected") {
        to = expense.SubmitterEmail || "";
      }
    }

    if (!to) {
      return res.status(400).json({
        error: "Could not resolve recipient. Pass `recipient` explicitly or ensure SubmitterEmail is set.",
      });
    }

    const expenseForTemplate = {
      ...expense,
      ApproverEmail:
        expense.ApproverEmail ||
        ((eventType === "expense.submitted" || eventType === "expense.resubmitted") ? to : expense.ApproverEmail),
    };

    setImmediate(() => safeNotify(eventType, { expense: expenseForTemplate, recipient: to }));

    return res.status(200).json({ accepted: true, recipient: to });
  } catch (err) {
    console.error("Error in /notify:", err);
    return res.status(500).json({ error: "Failed to enqueue notification" });
  }
});

module.exports = router;
