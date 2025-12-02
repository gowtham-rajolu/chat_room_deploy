const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const mongoose = require("mongoose");
require("dotenv").config();

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

const messageSchema = new mongoose.Schema({
  Name: String,
  content: String,
  timeStamp: { type: Date, default: Date.now },
});
const Message = mongoose.model("Message", messageSchema);

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

io.on("connection", async (socket) => {
  const oldMessages = await Message.find().sort({ timeStamp: 1 });
  socket.emit("load messages", oldMessages);

  socket.on("chat message", async (msg) => {
    const newMessage = new Message({
      Name: msg.Name,
      content: msg.msg,
    });
    await newMessage.save();
    io.emit("chat message", newMessage);
  });
});

server.listen(process.env.PORT || 3000);
