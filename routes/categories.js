// Per-tenant expense categories — CRUD.
//   GET    /categories?slug=      list
//   POST   /categories            create  { slug, name, color, icon, monthlyBudget, glAccount }
//   PUT    /categories/:id         update
//   DELETE /categories/:id         remove

const express = require("express");
const pool = require("../dbClient");

const router = express.Router();

function shape(r) {
  return {
    id: r.id,
    slug: r.slug,
    name: r.name,
    color: r.color,
    icon: r.icon,
    monthlyBudget: Number(r.monthly_budget) || 0,
    glAccount: r.gl_account || "",
    normalized: r.normalized || "",
    requiresBill: r.requires_bill !== false,
    excludedFromAutoApprove: r.excluded_from_auto_approve === true,
    enabled: r.enabled !== false,
    glProject: r.gl_project || "",
    glCrm: r.gl_crm || "",
    createdAt: r.created_at,
  };
}

router.get("/", async (req, res) => {
  const { slug } = req.query;
  if (!slug) return res.status(400).json({ error: "slug is required" });
  try {
    const { rows } = await pool.query(
      `SELECT * FROM expense_categories WHERE slug = $1 ORDER BY name ASC`,
      [slug],
    );
    return res.json(rows.map(shape));
  } catch (e) {
    console.error("Error fetching categories:", e);
    return res.status(500).json({ error: "Failed to fetch categories." });
  }
});

router.post("/", async (req, res) => {
  const { slug, name, color, icon, monthlyBudget, glAccount, glProject, glCrm } = req.body || {};
  if (!slug || !name) return res.status(400).json({ error: "slug and name are required" });
  try {
    const { rows } = await pool.query(
      `INSERT INTO expense_categories
         (slug, name, color, icon, monthly_budget, gl_account, gl_project, gl_crm)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [slug, name, color || "#6366F1", icon || "folder", Number(monthlyBudget) || 0,
       glAccount || "", glProject || "", glCrm || ""],
    );
    return res.status(201).json(shape(rows[0]));
  } catch (e) {
    console.error("Error creating category:", e);
    return res.status(500).json({ error: "Failed to create category." });
  }
});

router.put("/:id", async (req, res) => {
  const { name, color, icon, monthlyBudget, glAccount, glProject, glCrm } = req.body || {};
  try {
    const { rows } = await pool.query(
      `UPDATE expense_categories
          SET name = COALESCE($2, name),
              color = COALESCE($3, color),
              icon = COALESCE($4, icon),
              monthly_budget = COALESCE($5, monthly_budget),
              gl_account = COALESCE($6, gl_account),
              gl_project = COALESCE($7, gl_project),
              gl_crm = COALESCE($8, gl_crm)
        WHERE id = $1 RETURNING *`,
      [
        req.params.id,
        name ?? null,
        color ?? null,
        icon ?? null,
        monthlyBudget == null ? null : Number(monthlyBudget),
        glAccount ?? null,
        glProject ?? null,
        glCrm ?? null,
      ],
    );
    if (!rows.length) return res.status(404).json({ error: "Not found" });
    return res.json(shape(rows[0]));
  } catch (e) {
    console.error("Error updating category:", e);
    return res.status(500).json({ error: "Failed to update category." });
  }
});

router.delete("/:id", async (req, res) => {
  try {
    const { rowCount } = await pool.query(`DELETE FROM expense_categories WHERE id = $1`, [req.params.id]);
    if (!rowCount) return res.status(404).json({ error: "Not found" });
    return res.json({ deleted: true });
  } catch (e) {
    console.error("Error deleting category:", e);
    return res.status(500).json({ error: "Failed to delete category." });
  }
});

module.exports = router;
