'use strict';

const crypto = require('node:crypto');

function hashSecret(secret, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(secret), salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}

function verifySecret(secret, encoded) {
  try {
    const [kind, salt, expectedHex] = String(encoded).split(':');
    if (kind !== 'scrypt' || !salt || !expectedHex) return false;
    const actual = crypto.scryptSync(String(secret), salt, 64);
    const expected = Buffer.from(expectedHex, 'hex');
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function randomString(len = 12) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const bytes = crypto.randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i += 1) {
    out += chars[bytes[i] % chars.length];
  }
  return out;
}

function parseCookies(header = '') {
  return Object.fromEntries(
    String(header || '')
      .split(';')
      .map((part) => {
        const at = part.indexOf('=');
        if (at < 0) return ['', ''];
        try {
          return [
            decodeURIComponent(part.slice(0, at).trim()),
            decodeURIComponent(part.slice(at + 1).trim())
          ];
        } catch {
          return ['', ''];
        }
      })
      .filter(([key]) => key)
  );
}

class SessionManager {
  constructor(hours = 24) {
    this.ttlMs = hours * 60 * 60 * 1000;
    this.sessions = new Map();
  }

  setMaxAgeMinutes(minutes) {
    const num = Number(minutes);
    if (Number.isFinite(num) && num >= 5) {
      this.ttlMs = num * 60 * 1000;
    }
  }

  create(userId, username) {
    const id = randomToken(32);
    const session = {
      id,
      userId,
      username,
      csrf: randomToken(24),
      expiresAt: Date.now() + this.ttlMs
    };
    this.sessions.set(id, session);
    return session;
  }

  get(request) {
    const id = parseCookies(request.headers.cookie).ng_session;
    if (!id) return null;
    const session = this.sessions.get(id);
    if (!session || session.expiresAt <= Date.now()) {
      if (session) this.sessions.delete(id);
      return null;
    }
    return session;
  }

  delete(request) {
    const id = parseCookies(request.headers.cookie).ng_session;
    if (id) this.sessions.delete(id);
  }

  clearAll() {
    this.sessions.clear();
  }

  prune() {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (session.expiresAt <= now) this.sessions.delete(id);
    }
  }
}

module.exports = {
  hashSecret,
  verifySecret,
  randomToken,
  randomString,
  parseCookies,
  SessionManager
};
