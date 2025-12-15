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

/* ---------------- SCHEMAS ---------------- */
const messageSchema = new mongoose.Schema({
  name: String,
  content: String,
  timeStamp: { type: Date, default: Date.now }
});
const Message = mongoose.model("Message", messageSchema);

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
});
const User = mongoose.model("User", userSchema);

/* ---------------- AUTH (HTTP) ---------------- */
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
app.get("/", authMiddleware, (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/login.html");
});

app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/register.html");
});

/* ---------- REGISTER ---------- */
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ name, email, password: hashed });
  res.json({ msg: "Registered" });
});

/* ---------- LOGIN ---------- */
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ msg: "User not found" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ msg: "Wrong password" });

  const token = jwt.sign(
    { id: user._id, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: "15m" } // short-lived
  );

  // Cookie for HTTP routes
  res.cookie("Token", token, {
    httpOnly: true,
    sameSite: "lax"
  });

  // ALSO return token for Socket.IO
  res.json({ token });
});

/* ---------------- SOCKET AUTH (JWT) ---------------- */
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error("No token"));

  try {
    socket.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    next(new Error("Unauthorized"));
  }
});

/* ---------------- SOCKET EVENTS ---------------- */
io.on("connection", async (socket) => {
  console.log("Connected:", socket.user.name);

  const messages = await Message.find().sort({ timeStamp: 1 });
  socket.emit("load messages", messages);

  socket.on("chat message", async (text) => {
    const message = await Message.create({
      name: socket.user.name,   // ✅ FROM TOKEN
      content: text
    });
    io.emit("chat message", message);
  });
});

/* ---------------- START ---------------- */
server.listen(process.env.PORT || 3000, () =>
  console.log("Server running")
);
