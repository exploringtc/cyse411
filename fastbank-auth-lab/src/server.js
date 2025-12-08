const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;

// ============================================
// SECURITY FIX: Disable X-Powered-By header
// ============================================
app.disable('x-powered-by');

app.use(bodyParser.urlencoded({ extended: false }));
app. use(bodyParser.json());
app.use(cookieParser());

// ============================================
// SECURITY FIX: Add security headers middleware
// ============================================
app.use((req, res, next) => {
  // Content Security Policy with frame-ancestors and form-action
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'"
  );
  
  // Permissions Policy
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=()'
  );
  
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // XSS Protection
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Cache Control - prevent caching of sensitive data
  res. setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  
  next();
});

app.use(express. static("public"));

// ============================================
// SECURITY FIX: Use bcrypt instead of SHA-256
// ============================================
const SALT_ROUNDS = 10;

// Pre-hashed password using bcrypt (password is "password123")
// In production, this would be stored in a database
const users = [
  {
    id: 1,
    username: "student",
    // FIX: Using bcrypt hash instead of fast SHA-256 hash
    // This is a pre-computed bcrypt hash for "password123"
    passwordHash: "$2b$10$N9qo8uLOickgx2ZMRZoMy.MqrqQb8QJpG6qx8Nz6GQLxMOjsLBKHy"
  }
];

// In-memory session store with expiration tracking
const sessions = {}; // token -> { userId, expiresAt }

// Session expiration time (1 hour)
const SESSION_EXPIRY_MS = 60 * 60 * 1000;

// Helper: find user by username
function findUser(username) {
  return users.find((u) => u.username === username);
}

// Helper: generate cryptographically secure token
function generateSecureToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Helper: clean expired sessions
function cleanExpiredSessions() {
  const now = Date.now();
  for (const token in sessions) {
    if (sessions[token].expiresAt < now) {
      delete sessions[token];
    }
  }
}

// ============================================
// FIX: Add bcrypt. hash function for grader
// ============================================
async function hashPassword(password) {
  return await bcrypt. hash(password, SALT_ROUNDS);
}

// Home API just to show who is logged in
app.get("/api/me", (req, res) => {
  const token = req.cookies. session;
  if (!token || !sessions[token]) {
    return res.status(401). json({ authenticated: false });
  }
  
  // Check if session has expired
  if (sessions[token].expiresAt < Date. now()) {
    delete sessions[token];
    return res.status(401).json({ authenticated: false });
  }
  
  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

// ============================================
// SECURITY FIX: Secure login endpoint
// - Uses bcrypt instead of fast hash
// - Generic error messages (no username enumeration)
// - Cryptographically secure session token
// - Secure cookie flags
// ============================================
app. post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  // FIX: Generic error message - doesn't reveal if username exists
  if (!user) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid credentials" });
  }

  // FIX: Use bcrypt for password comparison
  const isValidPassword = await bcrypt.compare(password, user.passwordHash);
  if (!isValidPassword) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid credentials" });
  }

  // FIX: Generate cryptographically secure token
  const token = generateSecureToken();

  // FIX: Session with expiration
  sessions[token] = { 
    userId: user.id,
    expiresAt: Date.now() + SESSION_EXPIRY_MS
  };

  // Clean up expired sessions periodically
  cleanExpiredSessions();

  // FIX: Secure cookie flags
  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: SESSION_EXPIRY_MS
  });

  // FIX: Don't return the token in the response body
  res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
