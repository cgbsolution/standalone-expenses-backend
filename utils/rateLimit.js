// Fixed-window attempt counter, in memory.
//
// Per process: behind several instances each counts on its own, which still
// caps guessing at (instances × max) per window. Good enough for sign-in and
// password-reset abuse; not a general-purpose limiter.

function createLimiter({ windowMs, max }) {
  const hits = new Map();

  function prune(now) {
    for (const [key, entry] of hits) {
      if (entry.resetAt <= now) hits.delete(key);
    }
  }

  /** Count one attempt for `key`. Returns 0 when allowed, else seconds until the window resets. */
  return function hit(key) {
    const now = Date.now();
    if (hits.size > 10000) prune(now);
    let entry = hits.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
      hits.set(key, entry);
    }
    entry.count += 1;
    return entry.count <= max ? 0 : Math.ceil((entry.resetAt - now) / 1000);
  };
}

module.exports = { createLimiter };
