const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  googleId: String,
  username: String,
  email: { type: String, unique: true },
  image: String,
  country_code: { type: String, default: "+91" },
  phone: { type: String, default: null },
  gender: { type: String, enum: ['male', 'female', 'other'], default: null },
  dob: { type: Date, default: null },
  age: { type: Number },
  address: { type: String, default: null },
  isFirstLogin: { type: Boolean, default: true }
}, { timestamps: true });

userSchema.pre('save', function (next) {
  if (this.dob) {
    const today = new Date();
    let age = today.getFullYear() - this.dob.getFullYear();
    const m = today.getMonth() - this.dob.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < this.dob.getDate())) {
      age--;
    }
    this.age = age;
  }
  next();
});

module.exports = mongoose.model("users", userSchema);
