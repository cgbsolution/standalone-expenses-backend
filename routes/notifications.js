const express = require("express");
const pool = require("../dbClient");

const router = express.Router();

// Map a DB row to the shape the mobile app expects.
function rowToShape(row) {
  return {
    id: row.id,
    type: row.type,
    title: row.title,
    body: row.body,
    expenseId: row.expense_id || null,
    actorEmail: row.actor_email || null,
    read: row.read === true,
    createdAt: row.created_at,
  };
}

/**
 * @swagger
 * tags:
 *   name: Notifications
 *   description: In-app notification center (approval workflow events)
 */

/**
 * @swagger
 * /notifications:
 *   get:
 *     summary: List a user's in-app notifications (newest first)
 *     tags: [Notifications]
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema: { type: string }
 *       - in: query
 *         name: status
 *         schema: { type: string, enum: [all, unread], default: all }
 *       - in: query
 *         name: limit
 *         schema: { type: integer, default: 100 }
 *     responses:
 *       200: { description: List of notifications }
 *       400: { description: email is required }
 *       500: { description: Failed to fetch notifications }
 */
router.get("/", async (req, res) => {
  const { email, status, limit } = req.query;
  if (!email) return res.status(400).json({ error: "email is required" });

  const lim = Math.min(Math.max(Number(limit) || 100, 1), 200);
  try {
    const onlyUnread = String(status).toLowerCase() === "unread";
    const { rows } = await pool.query(
      `SELECT * FROM notifications
        WHERE LOWER(recipient_email) = LOWER($1)
          ${onlyUnread ? "AND read = FALSE" : ""}
        ORDER BY created_at DESC
        LIMIT $2`,
      [email, lim]
    );
    return res.json(rows.map(rowToShape));
  } catch (error) {
    console.error("Error fetching notifications:", error);
    return res.status(500).json({ error: "Failed to fetch notifications." });
  }
});

/**
 * @swagger
 * /notifications/unread-count:
 *   get:
 *     summary: Count unread notifications for a user
 *     tags: [Notifications]
 *     parameters:
 *       - in: query
 *         name: email
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: "{ count: number }" }
 *       400: { description: email is required }
 */
router.get("/unread-count", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: "email is required" });
  try {
    const { rows } = await pool.query(
      `SELECT COUNT(*)::int AS count
         FROM notifications
        WHERE LOWER(recipient_email) = LOWER($1) AND read = FALSE`,
      [email]
    );
    return res.json({ count: rows[0]?.count || 0 });
  } catch (error) {
    console.error("Error counting notifications:", error);
    return res.status(500).json({ error: "Failed to count notifications." });
  }
});

/**
 * @swagger
 * /notifications/read-all:
 *   put:
 *     summary: Mark all of a user's notifications as read
 *     tags: [Notifications]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email]
 *             properties:
 *               email: { type: string }
 *     responses:
 *       200: { description: "{ updated: number }" }
 *       400: { description: email is required }
 */
router.put("/read-all", async (req, res) => {
  const email = req.body?.email;
  if (!email) return res.status(400).json({ error: "email is required" });
  try {
    const { rowCount } = await pool.query(
      `UPDATE notifications
          SET read = TRUE
        WHERE LOWER(recipient_email) = LOWER($1) AND read = FALSE`,
      [email]
    );
    return res.json({ updated: rowCount });
  } catch (error) {
    console.error("Error marking all read:", error);
    return res.status(500).json({ error: "Failed to mark notifications read." });
  }
});

/**
 * @swagger
 * /notifications/{id}/read:
 *   put:
 *     summary: Mark a single notification as read
 *     tags: [Notifications]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200: { description: Updated notification }
 *       404: { description: Notification not found }
 */
router.put("/:id/read", async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE notifications SET read = TRUE WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: "Notification not found" });
    return res.json(rowToShape(rows[0]));
  } catch (error) {
    console.error("Error marking notification read:", error);
    return res.status(500).json({ error: "Failed to mark notification read." });
  }
});

module.exports = router;
