// Starts the API: brings the schema up to date, then listens. The app itself
// is defined in app.js so tests can load it without a server or a database.

const { app, ensureSchema } = require("./app");

const PORT = process.env.PORT || 5000;
ensureSchema().finally(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Swagger docs at http://localhost:${PORT}/api-docs`);
  });
  // Catch expenses written straight into the DB (chatbot inserts bypass the
  // API) and fire the notifications those rows never triggered.
  require("./pollers/expenseNotificationsPoller").start();
});
