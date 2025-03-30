// db.js
const mongoose = require("mongoose");

mongoose.connect("mongodb+srv://cs24m114:Aman9174245164@cluster0.yr1gsci.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0", {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection error:", err));

module.exports = mongoose;
