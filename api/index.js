// MEMOCON sync server - Vercel serverless version
// Talks to the MEMOCON app's built-in "Sync & Share" feature.
// Stores everything in Upstash Redis (connected via Vercel Storage) instead of a local file,
// since serverless functions don't keep local files between requests.

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { Redis } = require("@upstash/redis");

const redis = Redis.fromEnv();

const DB_KEY = "memocon:db";
const SECRETS_KEY = "memocon:secrets";

function emptyDb() {
  return {
    tenants: [],
    users: [],
    parties: [],
    items: [],
    sales: [],
    purchases: [],
    payments: [],
  };
}

async function loadDb() {
  const data = await redis.get(DB_KEY);
  if (!data) return emptyDb();
  return { ...emptyDb(), ...data };
}
async function saveDb(db) {
  await redis.set(DB_KEY, db);
}

async function loadOrCreateSecrets() {
  let secrets = await redis.get(SECRETS_KEY);
  if (!secrets) {
    secrets = {
      accessSecret: crypto.randomBytes(32).toString("hex"),
      refreshSecret: crypto.randomBytes(32).toString("hex"),
    };
    await redis.set(SECRETS_KEY, secrets);
  }
  return secrets;
}

const newId = () => crypto.randomUUID();
const now = () => new Date().toISOString();

// ---------- app setup ----------
const app = express();
app.use(cors());
app.use(express.json({ limit: "5mb" }));

app.get("/healthz", (req, res) => res.json({ ok: true }));
app.get("/", (req, res) => res.json({ ok: true, service: "memocon-server" }));

// ---------- auth helpers ----------
function signAccessToken(user, accessSecret) {
  return jwt.sign({ uid: user.id, tid: user.tenantId }, accessSecret, { expiresIn: "12h" });
}
function signRefreshToken(user, refreshSecret) {
  return jwt.sign({ uid: user.id, tid: user.tenantId, type: "refresh" }, refreshSecret, { expiresIn: "90d" });
}
async function authTokens(user) {
  const { accessSecret, refreshSecret } = await loadOrCreateSecrets();
  return {
    accessToken: signAccessToken(user, accessSecret),
    refreshToken: signRefreshToken(user, refreshSecret),
    tenantId: user.tenantId,
    userId: user.id,
  };
}
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const { accessSecret } = await loadOrCreateSecrets();
    const payload = jwt.verify(token, accessSecret);
    req.tenantId = payload.tid;
    req.userId = payload.uid;
    next();
  } catch {
    return res.status(401).json({ error: "Session expired, please log in again" });
  }
}

// ---------- auth routes ----------
app.post("/auth/signup", async (req, res) => {
  const { companyName, email, phone, password } = req.body || {};
  const identifier = (email || phone || "").trim().toLowerCase();
  if (!identifier || !password) {
    return res.status(400).json({ error: "Email/phone and password are required" });
  }
  const db = await loadDb();
  const existing = db.users.find(
    (u) => (email && u.email === email.trim().toLowerCase()) || (phone && u.phone === phone.trim())
  );
  if (existing) {
    return res.status(409).json({ error: "An account with that email or phone already exists" });
  }
  const tenant = { id: newId(), companyName: companyName || "My Company", createdAt: now() };
  const user = {
    id: newId(),
    tenantId: tenant.id,
    email: email ? email.trim().toLowerCase() : null,
    phone: phone ? phone.trim() : null,
    passwordHash: bcrypt.hashSync(password, 10),
    role: "owner",
    createdAt: now(),
  };
  db.tenants.push(tenant);
  db.users.push(user);
  await saveDb(db);
  res.json(await authTokens(user));
});

app.post("/auth/login", async (req, res) => {
  const { emailOrPhone, password } = req.body || {};
  const identifier = (emailOrPhone || "").trim().toLowerCase();
  const db = await loadDb();
  const user = db.users.find((u) => u.email === identifier || u.phone === (emailOrPhone || "").trim());
  if (!user || !bcrypt.compareSync(password || "", user.passwordHash)) {
    return res.status(401).json({ error: "Incorrect email/phone or password" });
  }
  res.json(await authTokens(user));
});

app.post("/auth/refresh", async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(400).json({ error: "Missing refresh token" });
  try {
    const { refreshSecret } = await loadOrCreateSecrets();
    const payload = jwt.verify(refreshToken, refreshSecret);
    const db = await loadDb();
    const user = db.users.find((u) => u.id === payload.uid);
    if (!user) return res.status(401).json({ error: "Account no longer exists" });
    res.json(await authTokens(user));
  } catch {
    res.status(401).json({ error: "Please log in again" });
  }
});

app.use(async (req, res, next) => {
  if (req.path.startsWith("/auth/")) return next();
  return requireAuth(req, res, next);
});

// ---------- generic tenant-scoped collection helpers ----------
function listOf(name) {
  return async (req, res) => {
    const db = await loadDb();
    const limit = Number(req.query.limit) || 200;
    const rows = db[name]
      .filter((r) => r.tenantId === req.tenantId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .slice(0, limit);
    res.json(rows);
  };
}
function createIn(name, shape) {
  return async (req, res) => {
    const db = await loadDb();
    const row = {
      id: newId(),
      tenantId: req.tenantId,
      ...shape(req.body || {}),
      status: "active",
      createdAt: now(),
      updatedAt: now(),
    };
    db[name].push(row);
    await saveDb(db);
    res.json(row);
  };
}
function updateIn(name) {
  return async (req, res) => {
    const db = await loadDb();
    const row = db[name].find((r) => r.id === req.params.id && r.tenantId === req.tenantId);
    if (!row) return res.status(404).json({ error: "Not found" });
    Object.assign(row, req.body || {}, { updatedAt: now() });
    await saveDb(db);
    res.json(row);
  };
}
function deleteIn(name) {
  return async (req, res) => {
    const db = await loadDb();
    const idx = db[name].findIndex((r) => r.id === req.params.id && r.tenantId === req.tenantId);
    if (idx === -1) return res.status(404).json({ error: "Not found" });
    db[name].splice(idx, 1);
    await saveDb(db);
    res.json({ ok: true });
  };
}
function getOne(name) {
  return async (req, res) => {
    const db = await loadDb();
    const row = db[name].find((r) => r.id === req.params.id && r.tenantId === req.tenantId);
    if (!row) return res.status(404).json({ error: "Not found" });
    res.json(row);
  };
}
function cancelIn(name) {
  return async (req, res) => {
    const db = await loadDb();
    const row = db[name].find((r) => r.id === req.params.id && r.tenantId === req.tenantId);
    if (!row) return res.status(404).json({ error: "Not found" });
    row.status = "cancelled";
    row.updatedAt = now();
    await saveDb(db);
    res.json(row);
  };
}

// ---------- parties ----------
app.get("/parties", listOf("parties"));
app.post(
  "/parties",
  createIn("parties", (b) => ({
    name: b.name,
    phone: b.phone || null,
    type: b.type || "customer",
    openingBalance: Number(b.openingBalance) || 0,
  }))
);
app.patch("/parties/:id", updateIn("parties"));
app.delete("/parties/:id", deleteIn("parties"));

// ---------- items ----------
app.get("/items", listOf("items"));
app.post(
  "/items",
  createIn("items", (b) => ({
    name: b.name,
    unit: b.unit || null,
    salePrice: Number(b.salePrice) || 0,
    purchasePrice: Number(b.purchasePrice) || 0,
    stockQty: Number(b.stockQty) || 0,
  }))
);
app.patch("/items/:id", updateIn("items"));
app.delete("/items/:id", deleteIn("items"));

// ---------- sales ----------
app.get("/sales", listOf("sales"));
app.post(
  "/sales",
  createIn("sales", (b) => ({
    partyId: b.partyId,
    invoiceNo: b.invoiceNo,
    items: b.items || [],
    received: Number(b.received) || 0,
  }))
);
app.patch("/sales/:id", updateIn("sales"));
app.post("/sales/:id/cancel", cancelIn("sales"));
app.get("/sales/:id", getOne("sales"));

// ---------- purchases ----------
app.get("/purchases", listOf("purchases"));
app.post(
  "/purchases",
  createIn("purchases", (b) => ({
    partyId: b.partyId,
    billNo: b.billNo,
    items: b.items || [],
    paid: Number(b.paid) || 0,
  }))
);
app.patch("/purchases/:id", updateIn("purchases"));
app.post("/purchases/:id/cancel", cancelIn("purchases"));
app.get("/purchases/:id", getOne("purchases"));

// ---------- payments ----------
app.get("/payments", listOf("payments"));
app.post(
  "/payments",
  createIn("payments", (b) => ({
    partyId: b.partyId,
    direction: b.direction === "out" ? "out" : "in",
    amount: Number(b.amount) || 0,
    splits: b.splits || null,
    links: b.links || null,
  }))
);
app.post("/payments/:id/cancel", cancelIn("payments"));
app.get("/payments/:id", getOne("payments"));

// ---------- licensing (lightweight local stub - real licensing lives in MEMOCON Control Center) ----------
app.get("/license-status", (req, res) => {
  res.json({ status: "active", plan: "free", validUntil: null });
});
app.get("/licenses", (req, res) => res.json([]));
app.post("/licenses/request", (req, res) => res.json({ ok: true }));
app.post("/licenses/:id/attach", (req, res) => res.json({ ok: true }));

// ---------- team users (so a second person can log in from another device) ----------
app.get("/users", async (req, res) => {
  const db = await loadDb();
  const rows = db.users
    .filter((u) => u.tenantId === req.tenantId)
    .map((u) => ({ id: u.id, email: u.email, phone: u.phone, role: u.role }));
  res.json(rows);
});
app.post("/users/invite", async (req, res) => {
  const { email, phone, password } = req.body || {};
  if (!password || (!email && !phone)) {
    return res.status(400).json({ error: "Email or phone and a password are required" });
  }
  const db = await loadDb();
  const exists = db.users.find(
    (u) => (email && u.email === email.trim().toLowerCase()) || (phone && u.phone === phone.trim())
  );
  if (exists) return res.status(409).json({ error: "That email or phone is already in use" });
  const user = {
    id: newId(),
    tenantId: req.tenantId,
    email: email ? email.trim().toLowerCase() : null,
    phone: phone ? phone.trim() : null,
    passwordHash: bcrypt.hashSync(password, 10),
    role: "staff",
    createdAt: now(),
  };
  db.users.push(user);
  await saveDb(db);
  res.json({ id: user.id, email: user.email, phone: user.phone, role: user.role });
});
app.delete("/users/:id", async (req, res) => {
  const db = await loadDb();
  const idx = db.users.findIndex((u) => u.id === req.params.id && u.tenantId === req.tenantId);
  if (idx === -1) return res.status(404).json({ error: "Not found" });
  db.users.splice(idx, 1);
  await saveDb(db);
  res.json({ ok: true });
});

app.use((req, res) => res.status(404).json({ error: "Unknown endpoint" }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

module.exports = app;
