const express = require("express");
const admin = require("firebase-admin");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const FIREBASE_CONFIG = process.env.FIREBASE_CONFIG;
const DB_URL = process.env.DB_URL;
const API_KEY = process.env.API_KEY;

if (!FIREBASE_CONFIG || !DB_URL || !API_KEY) {
  console.error("Missing ENV variables");
  process.exit(1);
}

let serviceAccount;
try {
  serviceAccount = JSON.parse(FIREBASE_CONFIG);
} catch (e) {
  console.error("Invalid FIREBASE_CONFIG");
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: DB_URL,
});

const db = admin.database();

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

function sha256Hex(text) {
  return crypto.createHash("sha256").update(String(text)).digest("hex");
}

function hmacHex(key, data) {
  return crypto.createHmac("sha256", String(key)).update(String(data)).digest("hex");
}

function timingSafeEqualText(a, b) {
  const aa = Buffer.from(String(a), "utf8");
  const bb = Buffer.from(String(b), "utf8");
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

function randomHex(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

function canonicalJson(value) {
  if (value === null || value === undefined) return "null";

  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }

  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    const items = keys.map((k) => {
      return JSON.stringify(k) + ":" + canonicalJson(value[k]);
    });
    return "{" + items.join(",") + "}";
  }

  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);

  return JSON.stringify(String(value));
}

function bearerToken(req) {
  const auth = req.headers.authorization || "";
  return auth.startsWith("Bearer ") ? auth.slice(7) : null;
}

async function authGuard(req, res, next) {
  try {
    if (req.headers["x-api-key"] !== API_KEY) {
      return res.status(403).json({ error: "forbidden" });
    }

    const token = bearerToken(req);
    if (!token) {
      return res.status(401).json({ error: "no token" });
    }

    const decoded = await admin.auth().verifyIdToken(token);
    req.uid = decoded.uid;
    req.email = decoded.email || null;
    req.name = decoded.name || null;
    next();
  } catch (e) {
    console.error("authGuard:", e);
    return res.status(401).json({ error: "invalid token" });
  }
}

async function verifySignedRequest(req, uid, bodyObj) {
  const deviceId = String(req.headers["x-device-id"] || "").trim();
  const sessionId = String(req.headers["x-session-id"] || "").trim();
  const timestamp = Number(req.headers["x-ts"] || 0);
  const nonce = String(req.headers["x-nonce"] || "").trim();
  const sign = String(req.headers["x-sign"] || "").trim();

  if (!deviceId || !sessionId || !timestamp || !nonce || !sign) {
    return { ok: false, status: 400, error: "missing signed data" };
  }

  if (Math.abs(Date.now() - timestamp) > 15000) {
    return { ok: false, status: 403, error: "expired" };
  }

  const sessionSnap = await db.ref(`sessions/${uid}/${sessionId}`).once("value");
  if (!sessionSnap.exists()) {
    return { ok: false, status: 403, error: "bad session" };
  }

  const session = sessionSnap.val() || {};

  if (session.used === true) {
    return { ok: false, status: 403, error: "session used" };
  }

  if (session.deviceId !== deviceId) {
    return { ok: false, status: 403, error: "device mismatch" };
  }

  if (session.expiresAt && Date.now() > session.expiresAt) {
    return { ok: false, status: 403, error: "session expired" };
  }

  const bodyCanonical = canonicalJson(bodyObj || {});
  const payload = [
    uid,
    req.method,
    req.path,
    deviceId,
    sessionId,
    session.challenge || "",
    timestamp,
    nonce,
    bodyCanonical,
  ].join("|");

  const expected = hmacHex(session.sessionKey, payload);

  if (!timingSafeEqualText(expected, sign)) {
    return { ok: false, status: 403, error: "bad signature" };
  }

  const nonceRef = db.ref(`nonces/${uid}/${sessionId}/${nonce}`);
  const nonceTx = await nonceRef.transaction((current) => {
    if (current === null) return Date.now();
    return;
  });

  if (!nonceTx.committed) {
    return { ok: false, status: 403, error: "replay" };
  }

  return { ok: true, deviceId, sessionId, session };
}

app.get("/", (req, res) => {
  res.send("🔥 Server Ready 🔥");
});

app.post("/session", authGuard, async (req, res) => {
  try {
    const uid = req.uid;
    const deviceId = String(req.body?.deviceId || "").trim();

    if (!deviceId) {
      return res.status(400).json({ error: "missing deviceId" });
    }

    const sessionId = randomHex(16);
    const sessionKey = randomHex(32);
    const challenge = randomHex(16);
    const expiresAt = Date.now() + 5 * 60 * 1000;

    await db.ref(`sessions/${uid}/${sessionId}`).set({
      sessionKey,
      deviceId,
      challenge,
      used: false,
      createdAt: Date.now(),
      expiresAt,
    });

    return res.json({
      sessionId,
      sessionKey,
      challenge,
      expiresAt,
    });
  } catch (e) {
    console.error("session error:", e);
    return res.status(500).json({ error: "server error" });
  }
});

app.post("/reward", authGuard, async (req, res) => {
  try {
    const uid = req.uid;

    const vr = await verifySignedRequest(req, uid, req.body || {});
    if (!vr.ok) {
      return res.status(vr.status).json({ error: vr.error });
    }

    const deviceId = vr.deviceId;
    const sessionId = vr.sessionId;

    const userRef = db.ref(`users/${uid}`);
    const tx = await userRef.transaction((current) => {
      const now = Date.now();

      if (current === null) {
        return {
          balance: 10,
          rewarded: true,
          deviceId,
          createdAt: now,
          updatedAt: now,
        };
      }

      if (current.deviceId && current.deviceId !== deviceId) {
        return;
      }

      if (current.rewarded === true) {
        return {
          ...current,
          updatedAt: now,
        };
      }

      return {
        ...current,
        balance: 10,
        rewarded: true,
        deviceId: current.deviceId || deviceId,
        updatedAt: now,
      };
    });

    if (!tx.committed) {
      return res.status(403).json({ error: "device mismatch" });
    }

    await db.ref(`sessions/${uid}/${sessionId}`).update({
      used: true,
      usedAt: Date.now(),
    });

    const user = tx.snapshot.val() || {};
    return res.json({
      balance: user.balance || 0,
      rewarded: !!user.rewarded,
    });
  } catch (e) {
    console.error("reward error:", e);
    return res.status(500).json({ error: "server error" });
  }
});

app.get("/balance", authGuard, async (req, res) => {
  try {
    const uid = req.uid;

    const vr = await verifySignedRequest(req, uid, {});
    if (!vr.ok) {
      return res.status(vr.status).json({ error: vr.error });
    }

    const snap = await db.ref(`users/${uid}`).once("value");
    const user = snap.val() || {};

    return res.json({
      balance: user.balance || 0,
      rewarded: !!user.rewarded,
    });
  } catch (e) {
    console.error("balance error:", e);
    return res.status(500).json({ error: "server error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("🔥 Server Running 🔥"));
