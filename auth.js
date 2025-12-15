const jwt = require("jsonwebtoken");
const SECRET_KEY = "your_secret_key"; // સાચું key લખો

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Access denied" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user; // JWT માંથી username મળે છે
    next();
  });
};

module.exports = authenticateToken;
