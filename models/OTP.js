const mongoose = require('mongoose');

const OTPSchema = new mongoose.Schema({
  email: { type: String },
  phone: { type: String },
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 300 } // 5 minutes expiry
});

module.exports = mongoose.model('OTP', OTPSchema);