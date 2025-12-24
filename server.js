const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");
const { log } = require("console");
require("dotenv").config();

/* ---------------- APP INIT ---------------- */
const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL,
    credentials: true
  }
});

app.use(express.json());
app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true
}));
app.use(cookieParser());

/* ---------------- DB ---------------- */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("Mongo error:", err));

/* ---------------- MAILER ---------------- */
const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASS
  }
});

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
  password: String,
  isVerified: { type: Boolean, default: false }
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

/* ---------------- ROUTES (STATIC) ---------------- */
app.get("/", authMiddleware, (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/login.html");
});

app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/register.html");
});

app.get("/reset-password", (req, res) => {
  res.sendFile(__dirname + "/reset-password.html");
});

/* ---------------- REGISTER + EMAIL VERIFY ---------------- */
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ msg: "All fields required" });
  }

  const exists = await User.findOne({ email });
  if (exists) {
    return res.status(409).json({ msg: "Email already registered" });
  }

  const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({
    name,
    email,
    password: hashed,
    isVerified: false
  });

  const emailToken = jwt.sign(
    { id: user._id },
    process.env.EMAIL_JWT_SECRET,
    { expiresIn: "5m" }
  );
  
  const link = `${process.env.CLIENT_URL}/verify-email?token=${emailToken}`;

  await mailer.sendMail({
    from: process.env.GMAIL_USER,
    to: email,
    subject: "Verify your email",
    html: `
      <h3>Email Verification</h3>
      <p>This link expires in 5 minutes.</p>
      <a href="${link}">Verify Email</a>
    `
  });

  res.json({ msg: "Registered. Check email to verify." });
});

/* ---------------- VERIFY EMAIL ---------------- */
app.get("/verify-email", async (req, res) => {
  try {
    const decoded = jwt.verify(req.query.token, process.env.EMAIL_JWT_SECRET);
    await User.findByIdAndUpdate(decoded.id, { isVerified: true });
    res.send("Email verified successfully. You can login now.");
  } catch {
    res.status(400).send("Invalid or expired verification link");
  }
});

/* ---------------- LOGIN ---------------- */
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ msg: "User not found" });
  if (!user.isVerified)
    return res.status(403).json({ msg: "Verify your email first" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ msg: "Wrong password" });

  const token = jwt.sign(
    { id: user._id, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: "15m" }
  );

  res.cookie("Token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/"
  });

  res.json({ token });
});

/* ---------------- LOGOUT ---------------- */
app.get("/logout", (req, res) => {
  res.clearCookie("Token", { path: "/" });
  res.send(`
    <script>
      localStorage.removeItem("Token");
      window.location.href="/login";
    </script>
  `);
});

/* ---------------- FORGOT PASSWORD ---------------- */
app.post("/api/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ msg: "If user exists, mail sent" });

  const user = await User.findOne({ email });
  if (!user) return res.json({ msg: "If user exists, mail sent" });

  const token = jwt.sign(
    { id: user._id },
    process.env.EMAIL_JWT_SECRET,
    { expiresIn: "5m" }
  );

  const link = `${process.env.CLIENT_URL}/reset-password?token=${token}`;

  await mailer.sendMail({
    from: process.env.GMAIL_USER,
    to: email,
    subject: "Reset Password",
    html: `
      <h3>Password Reset</h3>
      <p>This link expires in 5 minutes.</p>
      <a href="${link}">Reset Password</a>
    `
  });

  res.json({ msg: "Reset link sent" });
});

/* ---------------- RESET PASSWORD ---------------- */
app.post("/api/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ msg: "Invalid request" });
  }

  try {
    const decoded = jwt.verify(token, process.env.EMAIL_JWT_SECRET);
    const hashed = await bcrypt.hash(newPassword, 10);

    await User.findByIdAndUpdate(decoded.id, { password: hashed });
    res.json({ msg: "Password reset successful" });
  } catch {
    res.status(400).json({ msg: "Invalid or expired token" });
  }
});

/* ---------------- SOCKET AUTH ---------------- */
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
      name: socket.user.name,
      content: text
    });
    io.emit("chat message", message);
  });
});

/* ---------------- SAFETY ---------------- */
process.on("unhandledRejection", err => {
  console.error("Unhandled rejection:", err);
});

process.on("uncaughtException", err => {
  console.error("Uncaught exception:", err);
});

/* ---------------- START ---------------- */
server.listen(process.env.PORT || 3000, () => {
  console.log("Server running on port", process.env.PORT || 3000);
});
