// Per-tenant approval routing rules — CRUD (config only; the workflow engine
// reads these to decide auto-approve / routing once wired).
//   GET    /rules?slug=
//   POST   /rules            { slug, name, enabled, priority, conditions, action }
//   PUT    /rules/:id
//   DELETE /rules/:id

const express = require("express");
const pool = require("../dbClient");

const router = express.Router();

function shape(r) {
  return {
    id: r.id,
    slug: r.slug,
    name: r.name,
    enabled: r.enabled,
    priority: r.priority,
    conditions: r.conditions || {},
    action: r.action,
    createdAt: r.created_at,
  };
}

router.get("/", async (req, res) => {
  const { slug } = req.query;
  if (!slug) return res.status(400).json({ error: "slug is required" });
  try {
    const { rows } = await pool.query(
      `SELECT * FROM approval_rules WHERE slug = $1 ORDER BY priority ASC, created_at ASC`,
      [slug],
    );
    return res.json(rows.map(shape));
  } catch (e) {
    console.error("Error fetching rules:", e);
    return res.status(500).json({ error: "Failed to fetch rules." });
  }
});

router.post("/", async (req, res) => {
  const { slug, name, enabled, priority, conditions, action } = req.body || {};
  if (!slug || !name) return res.status(400).json({ error: "slug and name are required" });
  try {
    const { rows } = await pool.query(
      `INSERT INTO approval_rules (slug, name, enabled, priority, conditions, action)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [slug, name, enabled !== false, Number(priority) || 0, conditions || {}, action || "route"],
    );
    return res.status(201).json(shape(rows[0]));
  } catch (e) {
    console.error("Error creating rule:", e);
    return res.status(500).json({ error: "Failed to create rule." });
  }
});

router.put("/:id", async (req, res) => {
  const { name, enabled, priority, conditions, action } = req.body || {};
  try {
    const { rows } = await pool.query(
      `UPDATE approval_rules
          SET name = COALESCE($2, name),
              enabled = COALESCE($3, enabled),
              priority = COALESCE($4, priority),
              conditions = COALESCE($5, conditions),
              action = COALESCE($6, action)
        WHERE id = $1 RETURNING *`,
      [
        req.params.id,
        name ?? null,
        enabled == null ? null : enabled,
        priority == null ? null : Number(priority),
        conditions ?? null,
        action ?? null,
      ],
    );
    if (!rows.length) return res.status(404).json({ error: "Not found" });
    return res.json(shape(rows[0]));
  } catch (e) {
    console.error("Error updating rule:", e);
    return res.status(500).json({ error: "Failed to update rule." });
  }
});

router.delete("/:id", async (req, res) => {
  try {
    const { rowCount } = await pool.query(`DELETE FROM approval_rules WHERE id = $1`, [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: "Not found" });
    return res.json({ deleted: true });
  } catch (e) {
    console.error("Error deleting rule:", e);
    return res.status(500).json({ error: "Failed to delete rule." });
  }
});

module.exports = router;
