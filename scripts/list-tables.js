// Diagnostic: list all tables in every schema of the connected Supabase DB.
require("dotenv").config();
const pool = require("../dbClient");

(async () => {
  try {
    const { rows } = await pool.query(`
      SELECT table_schema, table_name
      FROM information_schema.tables
      WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
      ORDER BY table_schema, table_name
    `);
    if (!rows.length) {
      console.log("(no user tables in this database)");
    } else {
      console.log("schema.table");
      console.log("------------");
      rows.forEach((r) => console.log(`${r.table_schema}.${r.table_name}`));
    }
  } catch (err) {
    console.error("Query failed:", err.message);
  } finally {
    await pool.end();
  }
})();
