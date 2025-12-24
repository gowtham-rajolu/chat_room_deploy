/**
 * FULL SINGLE FILE – Gmail + Nodemailer
 * Run: node sendMail.js
 */

require("dotenv").config();
const nodemailer = require("nodemailer");

// 1️⃣ Create transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASS, // App Password (NOT gmail password)
  },
});

// 2️⃣ Send mail function
async function sendMail() {
  try {
    const info = await transporter.sendMail({
      from: `"gowtham's chat_room" <${process.env.GMAIL_USER}>`,
      to: "gowthamrajolu@gmail.com", // change this
      subject: "Test Mail from Node",
      text: "Hello! This email is sent using Nodemailer.",
      html: `
        <h2>Mail Working ✅</h2>
        <p>This email was sent using <b>Nodemailer + Gmail</b></p>
      `,
    });

    console.log("✅ Email sent successfully");
    console.log("Message ID:", info.messageId);
  } catch (err) {
    console.error("❌ Email sending failed");
    console.error(err);
  }
}

// 3️⃣ Call function
sendMail();
