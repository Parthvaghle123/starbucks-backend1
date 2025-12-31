const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const EmployeeSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  country_code: { type: String, default: "+91" },
  phone: { type: String, required: true },
  gender: { type: String, enum: ['male', 'female', 'other'], required: true },
  dob: { type: Date, required: true },
  age: { type: Number },  // 🟢 Stored Age Field
  address: { type: String, required: true },
  password: { type: String, required: true },

  cart: [
    {
      productId: Number,
      quantity: { type: Number, default: 1 }
    }
  ]
}, { timestamps: true });


// 📅 Auto-calculate age and hash password before saving
EmployeeSchema.pre('save', async function (next) {
  if (this.dob) {
    const today = new Date();
    let age = today.getFullYear() - this.dob.getFullYear();
    const m = today.getMonth() - this.dob.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < this.dob.getDate())) {
      age--;
    }
    this.age = age; // 🎯 Save age in DB
  }

  // Hash password if modified
  if (this.isModified('password')) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }

  next();
});

const EmployeeModel = mongoose.model("user", EmployeeSchema);
module.exports = EmployeeModel;
