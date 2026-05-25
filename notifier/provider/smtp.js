// SMTP email provider via nodemailer.
// Use this when you have working SMTP credentials (any provider — M365, Logix,
// SendGrid SMTP, Mailgun SMTP, on-prem Exchange, etc.).
//
// Required env (see .env.example):
//   SMTP_HOST     e.g. smtp.office365.com
//   SMTP_PORT     465 (implicit TLS) or 587 (STARTTLS)
//   SMTP_SECURE   "true" for 465, "false" for 587
//   SMTP_USER     login user (often the mailbox address)
//   SMTP_PASS     password / app password
//   SMTP_FROM     the From: address shown to recipients

const nodemailer = require("nodemailer");

let cachedTransporter = null;

function getTransporter() {
  if (cachedTransporter) return cachedTransporter;

  const host = process.env.SMTP_HOST;
  const port = parseInt(process.env.SMTP_PORT || "0", 10);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host || !port || !user || !pass) {
    throw new Error(
      "SMTP provider needs SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS"
    );
  }

  cachedTransporter = nodemailer.createTransport({
    host,
    port,
    secure: String(process.env.SMTP_SECURE).toLowerCase() === "true",
    auth: { user, pass },
    // Helpful when an SMTP server uses self-signed certs on an internal LAN.
    // Leave at default (true) for any public provider.
    tls: { rejectUnauthorized: process.env.SMTP_TLS_REJECT_UNAUTHORIZED !== "false" },
  });

  return cachedTransporter;
}

async function send({ to, subject, html }) {
  if (!to || !subject || !html) {
    throw new Error("send() requires { to, subject, html }");
  }
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  const transporter = getTransporter();
  const info = await transporter.sendMail({ from, to, subject, html });
  return { providerMessageId: info.messageId || null };
}

module.exports = { send };
