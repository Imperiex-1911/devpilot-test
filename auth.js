// auth.js — user authentication helpers (refactored for security)

const crypto = require('crypto');
const jwt    = require('jsonwebtoken');

const JWT_SECRET  = process.env.JWT_SECRET || 'dev-secret-change-in-prod';
const SALT_ROUNDS = 10;

// Replace MD5 with SHA-256 + salt
function hashPassword(password, salt) {
  if (!salt) salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.createHmac('sha256', salt).update(password).digest('hex');
  return { hash, salt };
}

function verifyPassword(password, storedHash, salt) {
  const { hash } = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(storedHash));
}

function validateUser(username, password, db) {
  const user = db.find(u => u.username === username);
  if (!user) return null;
  const valid = verifyPassword(password, user.passwordHash, user.salt);
  return valid ? user : null;
}

// Issue a signed JWT valid for 24h
function generateToken(userId, role) {
  return jwt.sign({ sub: userId, role }, JWT_SECRET, { expiresIn: '24h' });
}

// Middleware: verify JWT from Authorization header
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { hashPassword, verifyPassword, validateUser, generateToken, requireAuth };
