const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");
require("dotenv").config();

/* ---------------- APP INIT ---------------- */
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(express.json());
app.use(cors());
app.use(cookieParser());

/* ---------------- DB ---------------- */
mongoose.connect(process.env.MONGO_URI);

/* ---------------- Schemas ---------------- */
const messageSchema = new mongoose.Schema({
  Name: String,
  content: String,
  timeStamp: { type: Date, default: Date.now }
});
const Message = mongoose.model("Message", messageSchema);

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  timeStamp: { type: Date, default: Date.now }
});
const User = mongoose.model("User", userSchema);

/* ---------------- AUTH MIDDLEWARE ---------------- */
const authMiddleware = (req, res, next) => {
  const token = req.cookies?.Token;
  if (!token) return res.redirect("/login");

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.redirect("/login");
  }
};

/* ---------------- ROUTES ---------------- */

// MAIN CHAT (PROTECTED)
app.get("/", authMiddleware, (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// LOGIN
app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/login.html");
});

// REGISTER
app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/register.html");
});

/* ---------- Register API ---------- */
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ name, email, password: hashed });
  res.json({ msg: "User registered" });
});

/* ---------- Login API ---------- */
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ msg: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ msg: "Wrong password" });

  const token = jwt.sign(
    { id: user._id, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.cookie("Token", token, {
    httpOnly: true,
    sameSite: "lax"
  });

  res.json({ success: true });
});

/* ---------- Logout ---------- */
app.post("/logout", (req, res) => {
  res.clearCookie("Token");
  res.redirect("/login");
});

/* ---------------- SOCKET AUTH ---------------- */


io.on("connection", async (socket) => {
  const messages = await Message.find().sort({ timeStamp: 1 });
  socket.emit("load messages", messages);
  
  socket.on("chat message", async (msg) => {
    console.log(msg)
    const message = await Message.create(msg);
    io.emit("chat message", message);
  });
});

/* ---------------- START ---------------- */
server.listen(process.env.PORT || 3000, () =>
  console.log("Server running")
);
