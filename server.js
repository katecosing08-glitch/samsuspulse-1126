import express from "express";
import crypto from "node:crypto";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { readFile, writeFile } from "fs/promises";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DATA_FILE = join(__dirname, "data.json");

const app = express();
const PORT = process.env.PORT || 3000;
const PIN_TTL_MS = 5 * 60 * 1000; // 5 minutes

const pendingPins = new Map();

app.use(express.json());
app.use(express.static(join(__dirname, "public")));

const defaultData = {
  users: [],
  posts: [
    {
      id: 1,
      author: "Admin",
      role: "Admin",
      title: "Welcome to SamsusPulse",
      content: "Express.js backend is active and serving live board updates.",
      timestamp: new Date().toLocaleString()
    }
  ]
};

function hashValue(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function generateSixDigitPin() {
  return String(crypto.randomInt(100000, 1000000));
}

function normalizeDeviceKey(rawDevice) {
  const trimmed = String(rawDevice || "").trim();
  return (trimmed || "this-device").toLowerCase();
}

async function loadData() {
  try {
    const raw = await readFile(DATA_FILE, "utf-8");
    const parsed = JSON.parse(raw);
    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      posts: Array.isArray(parsed.posts) ? parsed.posts : []
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
  await writeFile(DATA_FILE, JSON.stringify(data, null, 2), "utf-8");
}

function canDeletePost(post, requester = {}) {
  const role = String(requester.role || "").toLowerCase();
  if (role === "admin" || role === "moderator") {
    return true;
  }
  const reqName = String(requester.name || requester.username || "").trim().toLowerCase();
  const postAuthor = String(post.author || "").trim().toLowerCase();
  return Boolean(reqName && postAuthor && reqName === postAuthor);
}

// POST /api/auth/request-pin - Generate a 6-digit PIN and deliver via on-screen Device Alert
app.post("/api/auth/request-pin", async (req, res) => {
  try {
    const { device, contact, email, name, role } = req.body || {};
    const rawTarget = String(device || contact || email || "This Device").trim() || "This Device";
    const deviceKey = normalizeDeviceKey(rawTarget);
    const cleanName = String(name || "").trim();
    const allowedRoles = [
      "ICT Student",
      "Web Developer",
      "UI/UX Designer",
      "Moderator",
      "Admin",
      "Guest Explorer",
      "Member"
    ];
    const requestedRole = allowedRoles.includes(role) ? role : "ICT Student";

    const store = await loadData();
    const existingUser = store.users.find(
      (u) => normalizeDeviceKey(u.device || u.contact || u.email) === deviceKey
    );

    const pin = generateSixDigitPin();
    const expiresAt = Date.now() + PIN_TTL_MS;

    pendingPins.set(deviceKey, {
      pinHash: hashValue(pin),
      expiresAt,
      name: existingUser?.name || existingUser?.username || cleanName || rawTarget,
      role: existingUser?.role || requestedRole
    });

    console.log(`[SamsusPulse Device Alert] Device: ${rawTarget} | PIN: ${pin} (expires in 5 mins)`);

    return res.json({
      message: `Device alert sent to ${rawTarget}.`,
      expiresInSeconds: PIN_TTL_MS / 1000,
      deviceAlert: {
        device: rawTarget,
        pin,
        expiresInMinutes: 5
      }
    });
  } catch {
    return res.status(500).json({ error: "Failed to trigger device alert." });
  }
});

// POST /api/auth/verify-pin - Verify the 6-digit PIN and create/return user session
app.post("/api/auth/verify-pin", async (req, res) => {
  try {
    const { device, contact, email, pin } = req.body || {};
    const rawTarget = String(device || contact || email || "This Device").trim() || "This Device";
    const deviceKey = normalizeDeviceKey(rawTarget);
    const cleanPin = String(pin || "").trim();

    if (!cleanPin) {
      return res.status(400).json({ error: "6-digit PIN is required." });
    }

    const challenge = pendingPins.get(deviceKey);
    if (!challenge) {
      return res.status(401).json({ error: "No active PIN found. Please send a new device alert." });
    }

    if (Date.now() > challenge.expiresAt) {
      pendingPins.delete(deviceKey);
      return res.status(401).json({ error: "This PIN has expired. Please send a new one." });
    }

    if (challenge.pinHash !== hashValue(cleanPin)) {
      return res.status(401).json({ error: "Invalid device PIN." });
    }

    pendingPins.delete(deviceKey);

    const store = await loadData();
    let user = store.users.find(
      (u) => normalizeDeviceKey(u.device || u.contact || u.email) === deviceKey
    );

    if (!user) {
      user = {
        id: Date.now(),
        name: challenge.name,
        username: challenge.name,
        device: rawTarget,
        role: challenge.role,
        authMethod: "device-alert",
        createdAt: new Date().toLocaleString()
      };
      store.users.push(user);
      await saveData(store);
    }

    return res.json({
      message: "Device PIN verified!",
      user: {
        id: user.id,
        name: user.name || user.username,
        device: user.device || rawTarget,
        role: user.role
      }
    });
  } catch {
    return res.status(500).json({ error: "PIN verification failed." });
  }
});

// GET /api/posts - Retrieve all live board posts
app.get("/api/posts", async (req, res) => {
  try {
    const store = await loadData();
    return res.json({ posts: store.posts });
  } catch {
    return res.status(500).json({ error: "Failed to load posts." });
  }
});

// POST /api/posts - Publish a new post to the live board
app.post("/api/posts", async (req, res) => {
  try {
    const { author, role, title, content } = req.body || {};
    const cleanTitle = String(title || "").trim();
    const cleanContent = String(content || "").trim();

    if (!cleanTitle || !cleanContent) {
      return res.status(400).json({ error: "Title and content are required." });
    }

    const store = await loadData();
    const nextId = store.posts.reduce((max, p) => Math.max(max, Number(p.id) || 0), 0) + 1;

    const newPost = {
      id: nextId,
      author: String(author || "Member").trim() || "Member",
      role: String(role || "Member").trim() || "Member",
      title: cleanTitle,
      content: cleanContent,
      timestamp: new Date().toLocaleString()
    };

    store.posts.unshift(newPost);
    await saveData(store);

    return res.status(201).json({ message: "Post published!", post: newPost });
  } catch {
    return res.status(500).json({ error: "Failed to publish post." });
  }
});

// DELETE /api/posts/:id - Delete a post if requester is author, Admin, or Moderator
app.delete("/api/posts/:id", async (req, res) => {
  try {
    const postId = Number(req.params.id);
    const requester = req.body || {};

    const store = await loadData();
    const index = store.posts.findIndex((p) => Number(p.id) === postId);

    if (index === -1) {
      return res.status(404).json({ error: "Post not found." });
    }

    const targetPost = store.posts[index];
    if (!canDeletePost(targetPost, requester)) {
      return res.status(403).json({
        error: "Only the post author, an Admin, or a Moderator can delete this post."
      });
    }

    store.posts.splice(index, 1);
    await saveData(store);

    return res.json({ message: "Post deleted.", deletedId: postId });
  } catch {
    return res.status(500).json({ error: "Failed to delete post." });
  }
});

app.listen(PORT, () => {
  console.log(`SamsusPulse Express server running on http://localhost:${PORT}`);
});
