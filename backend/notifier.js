// notifier.js
require("dotenv").config();
const nodemailer = require("nodemailer");
const { WebClient } = require("@slack/web-api");

// Configure nodemailer – using credentials from .env.
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Function to send an email notification.
function sendEmailNotification(subject, message, to = "amankmr636@gmail.com") {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    text: message,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("Error sending email:", error);
    } else {
      console.log("Email sent:", info.response);
    }
  });
}

// Configure Slack using your bot token from .env.
const slackToken = process.env.SLACK_BOT_TOKEN;
const slackClient = new WebClient(slackToken);

// Define Slack channel IDs to which notifications should be sent.
// Replace these with your actual channel IDs.
const channelIds = ["C08KZFX8WG3", "C08KUQFBBEH"];

// Function to send a Slack notification to multiple channels.
async function sendSlackNotification(message) {
  for (const channel of channelIds) {
    // Ensure the bot is a member of the channel.
    try {
      await slackClient.conversations.join({ channel });
    } catch (error) {
      // Ignore error if the bot is already in the channel.
      if (error.data && error.data.error === "already_in_channel") {
        console.log(`Already in channel ${channel}`);
      } else {
        console.error(`Error joining channel ${channel}:`, error);
      }
    }

    // Post the notification message.
    try {
      const res = await slackClient.chat.postMessage({
        channel,
        text: message,
      });
      console.log(`Slack message sent to ${channel}:`, res.ts);
    } catch (error) {
      console.error(`Error sending Slack message to ${channel}:`, error);
    }
  }
}

module.exports = { sendEmailNotification, sendSlackNotification };
