// rateLimit.js — simple in-memory rate limiter

const attempts = new Map();

const MAX_ATTEMPTS = 5;
const WINDOW_MS    = 15 * 60 * 1000; // 15 minutes

function checkRateLimit(ip) {
  const now  = Date.now();
  const entry = attempts.get(ip) || { count: 0, resetAt: now + WINDOW_MS };

  if (now > entry.resetAt) {
    entry.count   = 0;
    entry.resetAt = now + WINDOW_MS;
  }

  entry.count++;
  attempts.set(ip, entry);

  if (entry.count > MAX_ATTEMPTS) {
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
    return { allowed: false, retryAfter };
  }

  return { allowed: true };
}

function resetLimit(ip) {
  attempts.delete(ip);
}

module.exports = { checkRateLimit, resetLimit };
