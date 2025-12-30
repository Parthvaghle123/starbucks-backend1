const mongoose = require("mongoose");

const orderSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },  // 202501, 202502...
  username: String,
  email: String,
  address: String,
  phone: String,
  paymentMethod: String,
  payment_details: {
    cardNumber: { type: String, default: null },
    expiry: { type: String, default: null },
  },
  status: { type: String, default: "Approved" },
  cancelReason: { type: String, default: null },
  items: [
    {
      title: String,
      price: Number,
      quantity: Number,
      status: { type: String, default: "Approved" },
      total: Number,
    },
  ],
  total: Number,
  createdAt: { type: Date, default: Date.now },
});

// Auto-calculate total
orderSchema.pre("save", function (next) {
  this.items.forEach(item => {
    item.total = item.price * item.quantity;
  });
  this.total = this.items.reduce((sum, item) => sum + item.total, 0);
  next();
});

module.exports = mongoose.model("Order", orderSchema);
