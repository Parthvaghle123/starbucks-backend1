const mongoose = require("mongoose");

const cartSchema = new mongoose.Schema({
  userId: String,
  items: [
    {
      productId: String,
      image: String,
      title: String,
      price: Number,
      quantity: Number,
    },
  ],
});

module.exports = mongoose.model("Cart", cartSchema);
