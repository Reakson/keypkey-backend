const express = require("express");
const cors = require("cors");
require("dotenv").config();

const app = express(); // ✅ FIRST

const db = require("./config/db");
const authRoutes = require("./routes/authRoutes");

const vaultRoutes = require("./routes/vaultRoutes");

app.use(cors());
app.use(express.json());

app.use("/api/auth", authRoutes);
app.use("/api/password", vaultRoutes);


app.get("/", (req, res) => {
  res.send("Secure Password Manager API Running");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
