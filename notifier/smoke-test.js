// One-shot script: sends a single test "expense.submitted" email via SMTP.
// Reads creds from .env. Does not touch any HTTP routes or the database.
//
// Run from backend root:
//     npm run smoke-test:notify

require("dotenv").config();

const { notify } = require("./index");

const sampleExpense = {
  id: "smoke-test-1",
  ExpenseTitle: "Communication - WiFi Reimbursement",
  SubmitterEmail: process.env.SMTP_USER || "submitter@tatarealty.in",
  ApproverEmail: "manager@tatarealty.in",
  TotalAmount: 1982.43,
  SubmissionDate: new Date().toISOString().slice(0, 10),
  ExpenseData: [
    {
      BillNumber: "1234567890",
      ItemData: { DocumentNo: "1900002686" },
    },
  ],
};

async function main() {
  const recipient = process.env.NOTIFY_TEST_TO || process.env.SMTP_USER;
  if (!recipient) {
    throw new Error(
      "Set NOTIFY_TEST_TO (or SMTP_USER) in .env so I know where to send the test email."
    );
  }

  const provider = (process.env.NOTIFY_PROVIDER || "smtp").toLowerCase();
  console.log("→ provider  :", provider);
  console.log("→ host:port :", `${process.env.SMTP_HOST}:${process.env.SMTP_PORT}`);
  console.log("→ from      :", process.env.SMTP_FROM || process.env.SMTP_USER);
  console.log("→ recipient :", recipient);
  console.log("→ event     :", "expense.submitted");
  console.log("");

  try {
    const result = await notify("expense.submitted", {
      expense: sampleExpense,
      recipient,
    });
    console.log("sent:");
    console.log(JSON.stringify(result, null, 2));
    console.log("\nCheck the recipient's inbox (and Junk folder).");
  } catch (err) {
    console.error("failed:", err.message);
    if (/EAUTH|535|authentication/i.test(err.message)) {
      console.error("\nHint: SMTP auth failed. Verify SMTP_USER/SMTP_PASS.");
    }
    if (/ESOCKET|ETIMEDOUT|ECONNREFUSED/i.test(err.message)) {
      console.error("\nHint: Network error. Verify SMTP_HOST/SMTP_PORT and firewall.");
    }
    process.exit(1);
  }
}

main();
