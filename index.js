require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const session = require("express-session");
const passport = require("passport");
const OAuth2Strategy = require("passport-google-oauth2").Strategy;
const jwt = require("jsonwebtoken");


// Models
const User = require("./models/User");
const Cart = require("./models/Cart");
const Order = require("./models/Order");
const Product = require("./models/Product");
const User1 = require("./models/userSchema");
const OTP = require("./models/OTP");
const SibApiV3Sdk = require("sib-api-v3-sdk");


const app = express();
const PORT = process.env.PORT || 4500;
const SECRET_KEY = process.env.SECRET_KEY || "your_secret_key";
const FRONTEND_URL = process.env.NODE_ENV === 'production' 
  ? "https://starbucks-frontend1.vercel.app" 
  : "http://localhost:4800";

const clientid = "1020775716394-sv2kt9rb3urv0ugt0aq1bit0du3gle37.apps.googleusercontent.com"
const clientsecret ="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"


// ==================== MIDDLEWARE ====================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: ["http://localhost:4800", "https://starbucks-frontend1.vercel.app"], credentials: true }));

app.use(session({
  secret: "15672983hakdhfjkdsd",
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 7*24*60*60*1000, httpOnly: true, secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());
// ==================== GOOGLE OAUTH STRATEGY ====================
passport.use(new OAuth2Strategy({
  clientID: clientid,
  clientSecret: clientsecret,
  callbackURL: "https://starbucks-backend1.onrender.com/auth/google/callback",
  scope: ["profile","email"]
}, async (request, accessToken, refreshToken, profile, done) => {
  try {
    let user = await User1.findOne({ googleId: profile.id });
    if (!user) {
      user = new User1({
        googleId: profile.id,
        username: profile.displayName,
        email: profile.emails[0].value,
        image: profile.photos[0].value,
        country_code: "+91",
        phone: null,
        gender: null,
        dob: null,
        address: null
      });
      await user.save();
    }
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ==================== GOOGLE AUTH ROUTES ====================
app.get("/auth/google", passport.authenticate("google", { scope: ["profile","email"], accessType: "offline", prompt: "login" }));
app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "https://starbucks-frontend1.vercel.app/login" }), (req, res) => {
  // Generate JWT token for the authenticated user
  const token = jwt.sign({ id: req.user._id, email: req.user.email }, SECRET_KEY, { expiresIn: "1d" });
  
  const isProfileComplete = req.user.phone && req.user.gender && req.user.dob && req.user.address;
  const redirectPage = isProfileComplete ? "home" : "profile";
  
  // Render a page that sends token via postMessage and closes the popup
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Google Login</title>
      </head>
      <body>
        <script>
          if (window.opener) {
            window.opener.postMessage({
              token: '${token}',
              username: '${req.user.username}',
              redirectPage: '${redirectPage}'
            }, 'https://starbucks-frontend1.vercel.app');
            window.close();
          } else {
            window.location.href = 'https://starbucks-frontend1.vercel.app/${redirectPage}?token=${token}&username=${req.user.username}';
          }
        </script>
        <p>Closing window...</p>
      </body>
    </html>
  `);
});


// Connect MongoDB
mongoose.connect("mongodb+srv://vaghelasahil1402_db_user:parth@cluster0.ht5lfrp.mongodb.net/Starbucks")
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB error", err));

// Generate Unique 4 Digit Order ID
async function generateOrderId() {
  const year = new Date().getFullYear(); // Example: 2025

  const lastOrder = await Order.findOne({})
    .sort({ createdAt: -1 }) // લાસ્ટ ઓર્ડર લાવવો
    .limit(1);

  let nextSerial = 1; // First order

  if (lastOrder && lastOrder.orderId) {
    const lastId = parseInt(lastOrder.orderId);
    const lastYear = Math.floor(lastId / 1000); // Extract year from ID
    const lastSerial = lastId % 1000;

    if (lastYear === year) {
      nextSerial = lastSerial + 1;
    }
  }

  const paddedSerial = nextSerial.toString().padStart(3, "0"); // Example: "001"
  return `${year}${paddedSerial}`; // Example: "2025001"
}
// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Token required" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};
app.get("/user/profile1", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ email: user.email, phone: user.phone });
  } catch (err) {
    res.status(500).json({ message: "Error getting profile" });
  }
});

app.get("/user/profile", authenticateToken, async (req, res) => {
  try {
    let user = await User1.findById(req.user.id);
    if (!user) {
      user = await User.findById(req.user.id);
    }
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error getting profile" });
  }
});

app.put("/user/profile", authenticateToken, async (req, res) => {
  try {
    const { username, phone, gender, dob, address } = req.body;
    
    let user = await User1.findById(req.user.id);
    
    if (!user) {
      user = await User.findById(req.user.id);
    }
    
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (username) user.username = username;
    if (phone) user.phone = phone;
    if (gender) user.gender = gender;
    if (dob) user.dob = dob;
    if (address) user.address = address;

    await user.save();
    
    res.json({ success: true, message: "Profile updated successfully", user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error updating profile", error: err.message });
  }
});


// Brevo API setup
const defaultClient = SibApiV3Sdk.ApiClient.instance;
defaultClient.authentications["api-key"].apiKey =
  process.env.BREVO_API_KEY;

const emailApi = new SibApiV3Sdk.TransactionalEmailsApi();


// ================= OTP Generator =================
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

// ===================================================
// 🔐 STEP 1: VERIFY EMAIL & SEND OTP (FIXED)
// ===================================================
app.post("/verify-email-send-otp", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.json({ success: false, message: "Email not found" });
    }

    await OTP.deleteMany({ email: email.toLowerCase() });

    const otp = generateOTP();
    await OTP.create({ email: email.toLowerCase(), otp });

    const sendSmtpEmail = {
      to: [{ email }],
      sender: {
        name: "Starbucks",
        email: "vaghelasahil1402@gmail.com"
      },
      subject: "Password Reset OTP",
      htmlContent: `
        <div style="font-family:Arial">
          <h2>Password Reset OTP</h2>
          <h1 style="color:#00754a">${otp}</h1>
          <p>This OTP is valid for <b>5 minutes</b>.</p>
        </div>
      `
    };

    await emailApi.sendTransacEmail(sendSmtpEmail);

    if (process.env.NODE_ENV !== "production") {
      console.log("DEV OTP:", otp);
    }

    res.json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    console.error("Brevo Error:", err);
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

// ===================================================
// 🔐 STEP 2: VERIFY OTP
// ===================================================
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  try {
    const record = await OTP.findOne({ email: email.toLowerCase(), otp });
    if (!record) {
      return res.json({ success: false, message: "Invalid or expired OTP" });
    }

    await OTP.deleteOne({ _id: record._id });

    res.json({ success: true, message: "OTP verified" });
  } catch (err) {
    res.status(500).json({ success: false, message: "OTP verification failed" });
  }
});

// ===================================================
// 🔐 STEP 3: CHANGE PASSWORD
// ===================================================
app.post("/change-password-otp", async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    if (newPassword.length < 8) {
      return res.json({ success: false, message: "Minimum 8 characters" });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    user.password = newPassword;
    await user.save();

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Password update failed" });
  }
});
// Verify Email Exists (legacy - keeping for compatibility)
app.post("/verify-email", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email: email.toLowerCase() });

  if (user) {
    return res.json({ exists: true });
  } else {
    return res.json({ exists: false });
  }
});

app.post("/change-password", async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.json({ message: "User not found" });
    }

    // ✅ Check password length minimum 8
    if (newPassword.length < 8) {
      return res.json({ message: "Password must be at least 8 characters" });
    }

    user.password = newPassword; // Optional: Hash it if needed
    await user.save();

    res.json({ message: "Password updated successfully ✅" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error updating password" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (password.length < 8) {
    return res.json({ message: "Password must be at least 8 characters" });
  }

  const user = await User.findOne({ email: email.toLowerCase() });

  if (!user) {
    return res.json({ message: "No user found" });
  }

  if (user.password !== password) {
    return res.json({ message: "Password incorrect" });
  }

  const token = jwt.sign({ id: user._id, email: user.email }, SECRET_KEY, {
    expiresIn: "7d",
  });

  res.json({ message: "Success", token, username: user.username });
});

// Logout: mark user as inactive
app.post('/logout', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.status = 'inactive';
    await user.save();
    
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Failed to logout', error: err.message });
      }
      req.session.destroy((sessionErr) => {
        if (sessionErr) {
          return res.status(500).json({ success: false, message: 'Failed to destroy session', error: sessionErr.message });
        }
        res.json({ success: true });
      });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to logout', error: err.message });
  }
});

app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // ✅ Password length check
    if (password.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters" });
    }

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const newUser = await User.create({ ...req.body, email: email.toLowerCase() });
    res.status(200).json({ success: true, user: newUser });
  } catch (err) {
    res.status(500).json({ message: "Something went wrong", error: err });
  }
});

// Add to cart
app.post("/add-to-cart", authenticateToken, async (req, res) => {
  const { productId, image, title, price } = req.body;
  const userId = req.user.id;

  try {
    let cart = await Cart.findOne({ userId });

    if (!cart) {
      cart = new Cart({ userId, items: [] });
    }

    const existingItem = cart.items.find((item) => item.productId === productId);

    if (existingItem) {
      return res.status(400).json({ message: "Item already in cart" });
    } else {
      cart.items.push({ productId, image, title, price, quantity: 1 });
    }

    await cart.save();
    res.status(200).json({ message: "Item added to cart" });
  } catch (err) {
    res.status(500).json({ message: "Error", error: err.message });
  }
});

// Get cart
app.get("/cart", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const cart = await Cart.findOne({ userId });
    if (!cart) return res.json({ cart: [] });

    const fullCart = cart.items.map(item => ({
      ...item._doc,
      total: item.price * item.quantity
    }));

    res.json({ cart: fullCart });
  } catch (err) {
    res.status(500).json({ message: "Error", error: err.message });
  }
});app.put("/update-quantity/:productId", authenticateToken, async (req, res) => {
  const { productId } = req.params;
  const { action } = req.body;
  const userId = req.user.id;

  try {
    const cart = await Cart.findOne({ userId });
    const item = cart.items.find((item) => item.productId === productId);
    if (!item) return res.status(404).json({ message: "Item not found" });

    if (action === "increase") item.quantity += 1;
    if (action === "decrease") item.quantity -= 1;

    if (item.quantity <= 0) {
      cart.items = cart.items.filter((i) => i.productId !== productId);
    }

    await cart.save();
    res.status(200).json({ message: "Quantity updated" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Remove from cart
app.delete("/remove-from-cart/:productId", authenticateToken, async (req, res) => {
  const { productId } = req.params;
  const userId = req.user.id;

  try {
    const cart = await Cart.findOne({ userId });
    cart.items = cart.items.filter((item) => item.productId !== productId);
    await cart.save();
    res.status(200).json({ message: "Item removed" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Place Order API
app.post("/order", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { email, phone, address, paymentMethod, cardNumber, expiry } = req.body;

  try {
    const cart = await Cart.findOne({ userId });
    if (!cart || cart.items.length === 0) {
      return res.status(400).json({ message: "Cart is empty" });
    }

    const user = await User.findById(userId);
    const newOrderId = await generateOrderId(); // Call unique ID function

    const order = new Order({
      orderId: newOrderId,
      username: user.username,
      email,
      phone,
      address,
      paymentMethod,
      payment_details: {
        cardNumber: paymentMethod === "Card" ? cardNumber : null,
        expiry: paymentMethod === "Card" ? expiry : null,
      },
      items: cart.items,
    });

    await order.save();
    await Cart.findOneAndUpdate({ userId }, { items: [] });

    res.status(200).json({ message: "Order placed", orderId: newOrderId });
  } catch (err) {
    res.status(500).json({ message: "Order error", error: err.message });
  }
});

// Fetch orders
app.get("/orders", authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find({ email: req.user.email }).sort({ createdAt: -1 });
    res.status(200).json(orders);
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

// Cancel order
app.put("/api/cancel-order/:orderId", authenticateToken, async (req, res) => {
  const { orderId } = req.params;
  const { reason } = req.body;

  try {
    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: "Order not found" });

    if (order.email !== req.user.email) {
      return res.status(403).json({ message: "Unauthorized" });
    }

    if (order.status === "Cancelled") {
      return res.status(400).json({ message: "Order already cancelled" });
    }

    order.status = "Cancelled";
    order.cancelReason = reason;
    order.items.forEach(item => item.status = "Cancelled");

    await order.save();
    res.status(200).json({ message: "Order cancelled successfully" });
  } catch (err) {
    res.status(500).json({ message: "Cancel error", error: err.message });
  }
});

// Admin credentials (for demo; use env vars/db in production)
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin123';

// Admin login endpoint
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = jwt.sign({ admin: true, username }, SECRET_KEY, { expiresIn: '1d' });
    return res.json({ success: true, token });
  }
  res.json({ success: false, message: 'Invalid admin credentials' });
});

// Admin authentication middleware
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Admin token required' });
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err || !user.admin) return res.status(403).json({ message: 'Invalid admin token' });
    req.admin = user;
    next();
  });
};

// Admin: Get all users
app.get("/admin/users", authenticateAdmin, async (req, res) => {
  try {
    const [regularUsers, googleUsers] = await Promise.all([
      User.find({}).lean(),
      User1.find({}).lean()
    ]);

    const allUsers = [
      ...regularUsers.map(u => ({
        ...u,
        loginMethod: "email"
      })),
      ...googleUsers.map(u => ({
        ...u,
        loginMethod: "google"
      }))
    ];

    const userMap = new Map();
    for (const user of allUsers) {
      const email = user.email?.toLowerCase();
      if (email) {
        if (!userMap.has(email)) {
          userMap.set(email, user);
        } else {
          const existing = userMap.get(email);
          if (user.createdAt && (!existing.createdAt || new Date(user.createdAt) > new Date(existing.createdAt))) {
            userMap.set(email, user);
          }
        }
      } else {
        const id = user._id.toString();
        if (!userMap.has(id)) {
          userMap.set(id, user);
        }
      }
    }

    const uniqueUsers = Array.from(userMap.values()).map(user => ({
      ...user,
      createdAt: user.createdAt || new Date(parseInt(user._id.toString().substring(0, 8), 16) * 1000)
    }));

    uniqueUsers.sort((a, b) => {
      const dateA = new Date(a.createdAt);
      const dateB = new Date(b.createdAt);
      return dateB - dateA;
    });

    res.status(200).json(uniqueUsers);
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

// Admin: Get all orders
app.get("/admin/orders", authenticateAdmin, async (req, res) => {
  try {
    const orders = await Order.find({}).sort({ createdAt: -1 });
    res.status(200).json(orders);
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

// Admin dashboard stats endpoint
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const [totalUsers, totalOrders, orders] = await Promise.all([
      User.countDocuments(),
      Order.countDocuments(),
      Order.find({}).sort({ createdAt: -1 }).limit(5)
    ]);
    const totalRevenue = orders.reduce((sum, order) => sum + (order.total || 0), 0);
    res.json({
      totalUsers,
      totalOrders,
      totalRevenue,
      recentOrders: orders
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch dashboard stats', error: err.message });
  }
});

// Admin: Update order status
app.put('/admin/orders/:orderId/status', authenticateAdmin, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;
    
    // Validate status
    const validStatuses = ['Pending', 'Approved', 'Cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status provided' });
    }
    
    const order = await Order.findByIdAndUpdate(
      orderId, 
      { status, updatedAt: new Date() }, 
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    res.json({ success: true, message: `Order status updated to ${status}`, order });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update order status', error: err.message });
  }
});

// Admin: Delete user by ID
app.delete('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    await User.findByIdAndDelete(userId);
    // Optionally, delete related data (orders, carts, etc.)
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete user', error: err.message });
  }
});

// ==================== PRODUCT MANAGEMENT APIs ====================

// Get all products (public)
app.get('/api/products', async (req, res) => {
  try {
    const { category, featured, displayOnGift, displayOnMenu } = req.query;
    let filter = { isAvailable: true };
    
    if (category && category !== 'All') filter.category = category;
    if (featured === 'true') filter.featured = true;
    if (displayOnGift === 'true') filter.displayOnGift = true;
    if (displayOnMenu === 'true') filter.displayOnMenu = true;
    
    const products = await Product.find(filter).sort({ createdAt: -1 });
    res.json(products);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch products', error: err.message });
  }
});

// Admin: Get all products (with admin details)
app.get('/admin/products', authenticateAdmin, async (req, res) => {
  try {
    const products = await Product.find({}).sort({ createdAt: -1 });
    res.json(products);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch products', error: err.message });
  }
});

// Admin: Create new product
app.post('/admin/products', authenticateAdmin, async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json({ success: true, product, message: 'Product created successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to create product', error: err.message });
  }
});

// Admin: Update product
app.put('/admin/products/:id', authenticateAdmin, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }
    
    res.json({ success: true, product, message: 'Product updated successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to update product', error: err.message });
  }
});

// Admin: Delete product
app.delete('/admin/products/:id', authenticateAdmin, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }
    
    res.json({ success: true, message: 'Product deleted successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to delete product', error: err.message });
  }
});

// Admin: Toggle product availability
app.patch('/admin/products/:id/toggle-availability', authenticateAdmin, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }
    
    product.isAvailable = !product.isAvailable;
    await product.save();
    
    res.json({ 
      success: true, 
      product, 
      message: `Product ${product.isAvailable ? 'activated' : 'deactivated'} successfully` 
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to toggle product availability', error: err.message });
  }
});

// Admin: Toggle product display options
app.patch('/admin/products/:id/toggle-display', authenticateAdmin, async (req, res) => {
  try {
    const { displayType } = req.body; // 'gift' or 'menu'
    const product = await Product.findById(req.params.id);
    
    if (!product) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }
    
    if (displayType === 'gift') {
      product.displayOnGift = !product.displayOnGift;
    } else if (displayType === 'menu') {
      product.displayOnMenu = !product.displayOnMenu;
    }
    
    await product.save();
    
    res.json({ 
      success: true, 
      product, 
      message: `Product display on ${displayType} ${product[displayType === 'gift' ? 'displayOnGift' : 'displayOnMenu'] ? 'enabled' : 'disabled'}` 
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to toggle product display', error: err.message });
  }
});


// ==================== SMS OTP AUTHENTICATION ====================

// Send OTP API
app.post("/send-otp", async (req, res) => {
  try {
    const { phone } = req.body;
    
    if (!phone || phone.length !== 10) {
      return res.status(400).json({ success: false, message: "Valid 10-digit phone number required" });
    }

    // Delete existing OTP for this phone
    await OTP.deleteMany({ phone });

    // Generate new OTP
    const otp = generateOTP();
    
    // Save OTP to database
    await OTP.create({ phone, otp });
    
    res.json({ 
      success: true, 
      message: `OTP sent to +91${phone}`
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

// Verify OTP API (for SMS - keeping for future use)
app.post("/verify-sms-otp", async (req, res) => {
  try {
    const { phone, otp } = req.body;

    if (!phone || !otp) {
      return res.status(400).json({ success: false, message: "Phone and OTP required" });
    }

    // Find valid OTP
    const otpRecord = await OTP.findOne({ 
      phone, 
      otp
    });

    if (!otpRecord) {
      return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
    }

    // Delete used OTP
    await OTP.deleteOne({ _id: otpRecord._id });

    res.json({ 
      success: true, 
      message: "SMS OTP verified successfully"
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Verification failed" });
  }
});

// Resend OTP API
app.post("/resend-otp", async (req, res) => {
  try {
    const { phone } = req.body;
    
    if (!phone) {
      return res.status(400).json({ success: false, message: "Phone number required" });
    }

    // Delete existing OTP
    await OTP.deleteMany({ phone });

    // Generate new OTP
    const otp = generateOTP();
    
    // Save new OTP
    await OTP.create({ phone, otp });
    
    res.json({ 
      success: true, 
      message: "OTP resent successfully"
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to resend OTP" });
  }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

