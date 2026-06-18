const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Initialize Firebase Admin (credentials from environment variables)
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)),
    databaseURL: process.env.DATABASE_URL
  });
}
const db = admin.database();

// --- CONFIG (set these as Netlify environment variables) ---
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

// Simple router
exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Content-Type': 'application/json'
  };
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  const path = event.path.replace(/\/\.netlify\/functions\/api\/?/, '').split('/').filter(Boolean);
  const method = event.httpMethod;
  let body = {};
  try { body = JSON.parse(event.body || '{}'); } catch (e) {}

  try {
    // ── LOGIN ──
    if (path[0] === 'login' && method === 'POST') {
      const match = await bcrypt.compare(body.password, ADMIN_PASSWORD_HASH);
      if (!match) return { statusCode: 403, headers, body: JSON.stringify({ error: 'Wrong password' }) };
      const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
      return { statusCode: 200, headers, body: JSON.stringify({ token }) };
    }

    // ── GET CHANNELS (public) ──
    if (path[0] === 'channels' && method === 'GET') {
      const snap = await db.ref('channels').once('value');
      const channels = [];
      snap.forEach(child => {
        if (child.key && !child.key.startsWith('_')) channels.push({ id: child.key, ...child.val() });
      });
      return { statusCode: 200, headers, body: JSON.stringify(channels) };
    }

    // ── ADD CHANNEL (admin only) ──
    if (path[0] === 'channels' && method === 'POST') {
      verifyToken(event); // throws if invalid
      const { name, url, category, emoji, thumbnail } = body;
      const ref = db.ref('channels').push();
      await ref.set({ name, url, category, emoji, thumbnail });
      return { statusCode: 201, headers, body: JSON.stringify({ id: ref.key }) };
    }

    // ── DELETE CHANNEL (admin only) ──
    if (path[0] === 'channels' && path[1] && method === 'DELETE') {
      verifyToken(event);
      await db.ref(`channels/${path[1]}`).remove();
      return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
    }

    // ── EDIT CHANNEL (admin only) ──
    if (path[0] === 'channels' && path[1] && method === 'PUT') {
      verifyToken(event);
      const updates = {};
      if (body.name) updates.name = body.name;
      if (body.url) updates.url = body.url;
      if (body.category) updates.category = body.category;
      if (body.emoji) updates.emoji = body.emoji;
      if (body.thumbnail) updates.thumbnail = body.thumbnail;
      await db.ref(`channels/${path[1]}`).update(updates);
      return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
    }

    return { statusCode: 404, headers, body: JSON.stringify({ error: 'Not found' }) };
  } catch (err) {
    console.error(err);
    return { statusCode: err.statusCode || 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};

function verifyToken(event) {
  const authHeader = event.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) throw new Error('Missing token');
  const token = authHeader.split('Bearer ')[1];
  jwt.verify(token, JWT_SECRET);
}