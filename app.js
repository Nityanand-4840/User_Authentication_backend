const express = require("express");
const connectDB = require("./config/db");
const cors = require("cors");
const cookieParser = require("cookie-parser");

// Connect to MongoDB
connectDB();

const app = express();

app.use(
  cors({
    origin: "http://localhost:5173",
    methods: "GET,POST",
    allowedHeaders: "Content-Type,Authorization",
    credentials: true,
  })
);

app.use(cookieParser());

app.use(express.json()); // Middleware to parse JSON

const authRoutes = require("./routes/authRoutes");
app.use("/api/auth", authRoutes);

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
