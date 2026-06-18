const express = require("express");

const router = express.Router();

// Supabase Storage signing. Receipts live in a PRIVATE bucket, so the DB stores
// each file as an S3 URI (e.g. "s3://expense_receipt/<folder>/<file>"). The
// mobile app can't open those directly — it needs a short-lived HTTPS signed
// URL. We mint it here with the service-role key (never shipped to the client).

const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/+$/, "");
const SERVICE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || "";
const DEFAULT_BUCKET = process.env.SUPABASE_STORAGE_BUCKET || "expense_receipt";
const DEFAULT_EXPIRES_IN = 60 * 60; // 1 hour

// Turn whatever the DB stored into { bucket, path }.
// Accepts:  s3://bucket/folder/file.jpg
//           bucket/folder/file.jpg
//           folder/file.jpg            (uses DEFAULT_BUCKET)
//           https://<ref>.supabase.co/storage/v1/object/(public|sign)/bucket/path
function parseStorageRef(raw) {
  if (!raw || typeof raw !== "string") return null;
  let value = raw.trim();

  // Already a full http(s) URL — extract bucket/path if it's a Supabase
  // storage URL, otherwise treat the caller's value as final (pass through).
  const httpMatch = value.match(
    /\/storage\/v1\/object\/(?:public|sign|authenticated)\/([^/]+)\/(.+?)(?:\?|$)/i
  );
  if (httpMatch) {
    return { bucket: decodeURIComponent(httpMatch[1]), path: decodeURIComponent(httpMatch[2]) };
  }
  if (/^https?:\/\//i.test(value)) return { passthrough: value };

  // Strip s3:// (or any scheme://) prefix.
  value = value.replace(/^[a-z0-9]+:\/\//i, "");

  const segments = value.split("/").filter(Boolean);
  if (!segments.length) return null;

  // If the first segment is the known bucket, peel it off; otherwise assume the
  // whole thing is a path inside the default bucket.
  if (segments[0] === DEFAULT_BUCKET) {
    return { bucket: DEFAULT_BUCKET, path: segments.slice(1).join("/") };
  }
  return { bucket: DEFAULT_BUCKET, path: segments.join("/") };
}

function encodePath(path) {
  return path
    .split("/")
    .map((seg) => encodeURIComponent(seg))
    .join("/");
}

/**
 * @swagger
 * /storage/sign:
 *   get:
 *     summary: Return a short-lived HTTPS signed URL for a private storage object
 *     parameters:
 *       - in: query
 *         name: path
 *         required: true
 *         schema: { type: string }
 *         description: The stored blob_url (e.g. s3://expense_receipt/...) or object path
 *       - in: query
 *         name: expiresIn
 *         required: false
 *         schema: { type: integer }
 *         description: Seconds until the signed URL expires (default 3600)
 *     responses:
 *       200: { description: "{ url, expiresIn }" }
 *       400: { description: Missing or invalid path }
 *       500: { description: Signing failed / server misconfigured }
 */
router.get("/sign", async (req, res) => {
  try {
    const raw = req.query.path;
    const expiresIn = Math.min(
      Math.max(parseInt(req.query.expiresIn, 10) || DEFAULT_EXPIRES_IN, 60),
      60 * 60 * 24 * 7 // cap at 7 days
    );

    if (!raw) {
      return res.status(400).json({ error: "path is required" });
    }
    if (!SUPABASE_URL || !SERVICE_KEY) {
      console.error("[storage/sign] SUPABASE_URL or service key not configured");
      return res.status(500).json({ error: "Storage signing not configured" });
    }

    const ref = parseStorageRef(raw);
    if (!ref) {
      return res.status(400).json({ error: "Could not parse storage path" });
    }
    // Already a usable non-Supabase URL — hand it straight back.
    if (ref.passthrough) {
      return res.json({ url: ref.passthrough, expiresIn: 0 });
    }

    const signEndpoint = `${SUPABASE_URL}/storage/v1/object/sign/${encodeURIComponent(
      ref.bucket
    )}/${encodePath(ref.path)}`;

    const signResp = await fetch(signEndpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${SERVICE_KEY}`,
        apikey: SERVICE_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ expiresIn }),
    });

    const text = await signResp.text();
    let body = null;
    try {
      body = JSON.parse(text);
    } catch {
      /* non-JSON error body */
    }

    if (!signResp.ok || !body?.signedURL) {
      console.warn("[storage/sign] supabase sign failed:", signResp.status, text);
      return res
        .status(signResp.status === 404 ? 404 : 502)
        .json({ error: body?.message || "Failed to sign URL" });
    }

    // signedURL is relative: "/object/sign/<bucket>/<path>?token=..."
    const url = `${SUPABASE_URL}/storage/v1${body.signedURL}`;
    return res.json({ url, expiresIn });
  } catch (e) {
    console.error("[storage/sign] error:", e.message);
    return res.status(500).json({ error: "Internal error signing URL" });
  }
});

module.exports = router;
