
require("dotenv").config();

const express = require("express");
const path = require("path");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "10kb" }));

app.use(
    "/api/",
    rateLimit({
        windowMs: 60 * 1000,
        limit: 20,
        standardHeaders: "draft-7",
        legacyHeaders: false
    })
);

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/style.css", (req, res) => {
    res.sendFile(path.join(__dirname, "style.css"));
});

app.get("/script.js", (req, res) => {
    res.sendFile(path.join(__dirname, "script.js"));
});

app.get("/api/health", (req, res) => {
    res.json({ status: "ok" });
});

app.listen(PORT, () => {
    console.log(`Fake or Real running at http://localhost:${PORT}`);
});
