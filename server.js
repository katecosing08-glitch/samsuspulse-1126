import express from "express";
import crypto from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { readFile, writeFile } from "node:fs/promises";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DATA_FILE = join(__dirname, "data.json");

const app = express();
const PORT = process.env.PORT || 3000;
const PIN_TTL_MS = 5 * 60 * 1000; // 5 minutes
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

const ALLOWED_ROLES = new Set(["Admin", "Member", "Guest"]);

const pendingPins = new Map();
const sessions = new Map();

app.use(express.json());
app.use(express.static(join(__dirname, "public")));

const defaultData = {
  users: [],
  posts: [
    {
      id: 1,
      author: "SamsusPulse System",
      role: "Admin",
      title: "Welcome to SamsusPulse",
      content: "Express.js backend is active and serving live board updates.",
      timestamp: new Date().toLocaleString()
    }
  ]
};

function normalizeRole(rawRole) {
  const cleaned = String(rawRole || "").trim();
  if (!cleaned) return "Member";
  const matched = Array.from(ALLOWED_ROLES).find(
    (r) => r.toLowerCase() === cleaned.toLowerCase()
  );
  return matched || "Member";
}

function normalizeName(rawName, role) {
  const cleaned = String(rawName || "").trim();
  if (cleaned) return cleaned.slice(0, 60);
  return role === "Guest" ? "Guest" : "Member";
}

function hashValue(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function generateSixDigitPin() {
  return String(crypto.randomInt(0, 1000000)).padStart(6, "0");
}

async function loadData() {
  try {
    const raw = await readFile(DATA_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      posts: Array.isArray(parsed.posts) ? parsed.posts : [...defaultData.posts]
    };
  } catch {
    await saveData(defaultData);
    return {
      users: [...defaultData.users],
      posts: [...defaultData.posts]
    };
  }
}

async function saveData(data) {
  await writeFile(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}

function extractToken(req) {
  const authHeader = req.get("authorization") || "";
  if (authHeader.startsWith("Bearer ")) {
    return authHeader.slice(7).trim();
  }
  const cookieHeader = req.get("cookie") || "";
  const match = cookieHeader
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith("samsuspulse_token="));
  return match ? decodeURIComponent(match.slice("samsuspulse_token=".length)) : "";
}

function getAuthenticatedUser(req) {
  const token = extractToken(req);
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    return null;
  }
  return {
    token,
    user: {
      id: session.user.id,
      name: session.user.name,
      role: session.user.role,
      device: session.user.device
    }
  };
}

// Return current visitor identity (Guest if not signed in)
app.get("/api/auth/me", (req, res) => {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return res.json({
      authenticated: false,
      user: { name: "Guest", role: "Guest" }
    });
  }
  return res.json({
    authenticated: true,
    user: auth.user
  });
});

// Step 1: Request a 6-digit PIN tied to a specific requestId, name, role, and device
app.post("/api/auth/request-pin", async (req, res) => {
  const device = String(req.body?.device || "This Device").trim().slice(0, 80) || "This Device";
  const role = normalizeRole(req.body?.role);
  const name = normalizeName(req.body?.name, role);

  if (role !== "Guest" && !String(req.body?.name || "").trim()) {
    return res.status(400).json({ error: "Please enter your display name." });
  }

  const pin = generateSixDigitPin();
  const requestId = crypto.randomUUID();
  const expiresAt = Date.now() + PIN_TTL_MS;

  pendingPins.set(requestId, {
    requestId,
    device,
    name,
    role,
    pinHash: hashValue(pin),
    expiresAt,
    attempts: 0
  });

  return res.json({
    requestId,
    message: `6-digit PIN generated for ${name} (${role}).`,
    deviceAlert: {
      requestId,
      device,
      name,
      role,
      pin,
      expiresInMinutes: 5
    }
  });
});

// Step 2: Verify PIN and create an isolated user session
app.post("/api/auth/verify-pin", async (req, res) => {
  const requestId = String(req.body?.requestId || "").trim();
  const pin = String(req.body?.pin || "").trim();

  if (!/^\d{6}$/.test(pin)) {
    return res.status(400).json({ error: "Please enter a valid 6-digit PIN." });
  }

  const entry = requestId ? pendingPins.get(requestId) : null;
  if (!entry) {
    return res.status(400).json({ error: "PIN request not found or expired. Please request a new PIN." });
  }

  if (Date.now() > entry.expiresAt) {
    pendingPins.delete(requestId);
    return res.status(400).json({ error: "PIN has expired. Please request a new PIN." });
  }

  if (entry.attempts >= 5) {
    pendingPins.delete(requestId);
    return res.status(429).json({ error: "Too many invalid attempts. Please request a new PIN." });
  }

  if (hashValue(pin) !== entry.pinHash) {
    entry.attempts += 1;
    return res.status(401).json({ error: "Incorrect PIN. Try again." });
  }

  pendingPins.delete(requestId);

  const data = await loadData();
  const existingIndex = data.users.findIndex(
    (u) =>
      String(u.name || "").trim().toLowerCase() === entry.name.toLowerCase() &&
      String(u.role || "").trim().toLowerCase() === entry.role.toLowerCase()
  );

  let savedUser;
  if (existingIndex >= 0) {
    savedUser = {
      ...data.users[existingIndex],
      name: entry.name,
      role: entry.role,
      device: entry.device,
      lastLoginAt: new Date().toISOString()
    };
    data.users[existingIndex] = savedUser;
  } else {
    savedUser = {
      id: crypto.randomUUID(),
      name: entry.name,
      role: entry.role,
      device: entry.device,
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString()
    };
    data.users.push(savedUser);
  }

  await saveData(data);

  const token = crypto.randomBytes(32).toString("hex");
  const sessionUser = {
    id: savedUser.id,
    name: savedUser.name,
    role: savedUser.role,
    device: savedUser.device
  };

  sessions.set(token, {
    user: sessionUser,
    expiresAt: Date.now() + SESSION_TTL_MS
  });

  res.cookie("samsuspulse_token", token, {
    httpOnly: true,
    sameSite: "lax",
    maxAge: SESSION_TTL_MS
  });

  return res.json({
    message: `Signed in as ${sessionUser.name} (${sessionUser.role}).`,
    token,
    user: sessionUser
  });
});

app.post("/api/auth/logout", (req, res) => {
  const token = extractToken(req);
  if (token) sessions.delete(token);
  res.clearCookie("samsuspulse_token");
  return res.json({ ok: true });
});

app.get("/api/posts", async (req, res) => {
  const data = await loadData();
  return res.json({ posts: data.posts });
});

app.post("/api/posts", async (req, res) => {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return res.status(401).json({ error: "Please sign in as a Member or Admin to publish posts." });
  }

  if (auth.user.role === "Guest") {
    return res.status(403).json({ error: "Guests cannot publish to the live board. Please sign in as a Member or Admin." });
  }

  const title = String(req.body?.title || "").trim();
  const content = String(req.body?.content || "").trim();

  if (!title || !content) {
    return res.status(400).json({ error: "Title and content are required." });
  }

  const data = await loadData();
  const nextId = data.posts.reduce((max, p) => Math.max(max, Number(p.id) || 0), 0) + 1;

  const newPost = {
    id: nextId,
    author: auth.user.name,
    role: auth.user.role,
    title: title.slice(0, 140),
    content: content.slice(0, 4000),
    timestamp: new Date().toLocaleString()
  };

  data.posts.unshift(newPost);
  await saveData(data);

  return res.status(201).json({ post: newPost });
});

app.delete("/api/posts/:id", async (req, res) => {
  const auth = getAuthenticatedUser(req);
  if (!auth) {
    return res.status(401).json({ error: "Please sign in to delete posts." });
  }

  const postId = Number(req.params.id);
  const data = await loadData();
  const index = data.posts.findIndex((p) => Number(p.id) === postId);

  if (index === -1) {
    return res.status(404).json({ error: "Post not found." });
  }

  const targetPost = data.posts[index];
  const isAdmin = auth.user.role.toLowerCase() === "admin";
  const isAuthor =
    String(targetPost.author || "").trim().toLowerCase() ===
    String(auth.user.name || "").trim().toLowerCase();

  if (!isAdmin && !isAuthor) {
    return res.status(403).json({ error: "Only Admins or the post author can delete this post." });
  }

  data.posts.splice(index, 1);
  await saveData(data);

  return res.json({ ok: true, deletedId: postId });
});

app.listen(PORT, () => {
  console.log(`SamsusPulse server running at http://localhost:${PORT}`);
});
