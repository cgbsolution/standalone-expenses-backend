const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const swaggerJsDoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ limit: "25mb", extended: true }));

const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Expense Tracker API",
      version: "1.0.0",
      description: "API to manage expenses (Master Expenses, Invoices, etc.)",
    },
    servers: [
      {
        url: process.env.BASE_URL || `http://localhost:${process.env.PORT || 5000}`,
      },
    ],
  },
  apis: ["./routes/*.js"],
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocs));

const masterExpenseRoute = require("./routes/masterExpense");
app.use("/master-expense", masterExpenseRoute);

const authRoute = require("./routes/auth");
app.use("/auth", authRoute);

const usersRoute = require("./routes/users");
app.use("/users", usersRoute);

const tenantsRoute = require("./routes/tenants");
app.use("/tenants", tenantsRoute);

const adminRoute = require("./routes/admin");
app.use("/admin", adminRoute);

app.get("/", (req, res) => {
  res.status(200).json({ status: "OK", message: "Expense Tracker API running" });
});

app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error("Server Error:", err.stack);
  res.status(500).json({ error: "Internal Server Error" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Swagger docs at http://localhost:${PORT}/api-docs`);
});
