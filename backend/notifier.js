require("dotenv").config();
const nodemailer = require("nodemailer");
const { WebClient } = require("@slack/web-api");

// Configure nodemailer – Use environment variables for security.
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER, // Store in .env
    pass: process.env.EMAIL_PASS  // Store in .env
  }
});

// Function to send an email notification.
function sendEmailNotification(subject, message, to = "amankmr636@gmail.com") {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    text: message
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
    } else {
      console.log("Email sent:", info.response);
    }
  });
}

// Configure Slack
const slackToken = process.env.SLACK_BOT_TOKEN; // Store in .env
const slackClient = new WebClient(slackToken);

// Define Slack channels
const channelIds = ["C08KZFX8WG3", "C08KUQFBBEH"]; // Replace with actual channel IDs

// Function to send a Slack notification to multiple channels.
async function sendSlackNotification(message) {
  try {
    for (const channel of channelIds) {
      const res = await slackClient.chat.postMessage({
        channel,
        text: message
      });
      console.log(`Slack message sent to ${channel}:`, res.ts);
    }
  } catch (error) {
    console.error("Error sending Slack message:", error);
  }
}

module.exports = { sendEmailNotification, sendSlackNotification };