// Supabase Storage helpers for PUBLIC objects (e.g. profile avatars).
//
// Unlike receipts (private bucket + signed URLs, see routes/storage.js), avatars
// are non-sensitive and shown everywhere, so we keep them in a PUBLIC bucket and
// store the plain HTTPS URL on the row. No signing round-trip on every render.
//
// All calls use the service-role key, which never leaves the server.

const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/+$/, "");
const SERVICE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || "";

function isConfigured() {
  return Boolean(SUPABASE_URL && SERVICE_KEY);
}

// Buckets we've already confirmed/created this process — avoids a network round
// trip on every upload after the first.
const ensuredBuckets = new Set();

/**
 * Create a public bucket if it doesn't exist yet. Idempotent: a 400/409 from an
 * already-existing bucket is treated as success.
 */
async function ensurePublicBucket(bucket) {
  if (ensuredBuckets.has(bucket)) return;
  if (!isConfigured()) throw new Error("Supabase storage not configured");

  const resp = await fetch(`${SUPABASE_URL}/storage/v1/bucket`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${SERVICE_KEY}`,
      apikey: SERVICE_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ id: bucket, name: bucket, public: true }),
  });

  if (resp.ok || resp.status === 400 || resp.status === 409) {
    // 400/409 → "already exists". Either way the bucket is now usable.
    ensuredBuckets.add(bucket);
    return;
  }
  const text = await resp.text().catch(() => "");
  throw new Error(`Failed to ensure bucket "${bucket}": ${resp.status} ${text}`);
}

/**
 * Upload a buffer to a public bucket (upsert) and return its public HTTPS URL.
 * @returns {Promise<string>} the public object URL
 */
async function uploadPublicObject({ bucket, path, buffer, contentType }) {
  if (!isConfigured()) throw new Error("Supabase storage not configured");
  await ensurePublicBucket(bucket);

  const encodedPath = path
    .split("/")
    .map((seg) => encodeURIComponent(seg))
    .join("/");

  const resp = await fetch(
    `${SUPABASE_URL}/storage/v1/object/${encodeURIComponent(bucket)}/${encodedPath}`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${SERVICE_KEY}`,
        apikey: SERVICE_KEY,
        "Content-Type": contentType || "application/octet-stream",
        "x-upsert": "true",
        "cache-control": "3600",
      },
      body: buffer,
    },
  );

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Upload failed: ${resp.status} ${text}`);
  }

  return `${SUPABASE_URL}/storage/v1/object/public/${encodeURIComponent(
    bucket,
  )}/${encodedPath}`;
}

module.exports = { isConfigured, ensurePublicBucket, uploadPublicObject };
