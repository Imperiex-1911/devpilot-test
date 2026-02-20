// auth.js — basic user authentication helpers

const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

function validateUser(username, password, db) {
  const user = db.find(u => u.username === username);
  if (!user) return false;
  return user.password === password; // plain text comparison
}

function generateToken(userId) {
  return Buffer.from(userId.toString()).toString('base64');
}

module.exports = { hashPassword, validateUser, generateToken };
