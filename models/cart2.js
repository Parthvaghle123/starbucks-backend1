const express = require("express");
const router = express.Router();
const authenticateToken = require("./auth"); // if using JWT
const User = require("./models/User");
const Cart = require("./models/Cart");
const Order = require("./models/Order");

// Add item to cart
router.post("/add-to-cart", authenticateToken, async (req, res) => {
  const { productId, image, title, price } = req.body;
  const userId = req.user.id;

  try {
    let cart = await Cart.findOne({ userId });

    if (!cart) {
      cart = new Cart({ userId, items: [] });
    }

    const existingItem = cart.items.find((item) => item.productId === productId);

    if (existingItem) {
      // ❌ Duplicate મળ્યું => જવાબ મોકલવો
      return res.status(400).json({ message: "Item already in cart" });
    } else {
      // ✅ Item પહેલેથી નથી => Add કરો
      cart.items.push({ productId, image, title, price, quantity: 1 });
    }

    await cart.save();
    res.status(200).json({ message: "Item added to cart" });
  } catch (err) {
    res.status(500).json({ message: "Error", error: err.message });
  }
});


// Update quantity
router.put("/update-cart", authenticateToken, async (req, res) => {
  const { productId, quantity } = req.body;
  const userId = req.user.id;

  try {
    const cart = await Cart.findOne({ userId });
    const item = cart.items.find((item) => item.productId === productId);
    if (item) {
      item.quantity = quantity;
    }
    await cart.save();
    res.status(200).json({ message: "Quantity updated" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Remove item
router.delete("/remove-cart/:productId", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { productId } = req.params;

  try {
    const cart = await Cart.findOne({ userId });
    cart.items = cart.items.filter((item) => item.productId !== productId);
    await cart.save();
    res.status(200).json({ message: "Item removed" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/orders", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const orders = await Order.find({ username: req.user.username }).sort({ createdAt: -1 });
    res.status(200).json(orders);
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

module.exports = router;
