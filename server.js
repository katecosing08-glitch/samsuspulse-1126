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

function hashPassword(password) {
  return crypto.createHash("sha256").update(String(password)).digest("hex");
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

// POST /api/signup - Create a persistent member account
app.post("/api/signup", async (req, res) => {
  try {
    const { name, email, password, role } = req.body || {};
    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "").trim().toLowerCase();
    const rawPassword = String(password || "");
    const allowedRoles = ["ICT Student", "Web Developer", "UI/UX Designer", "Moderator", "Admin", "Guest Explorer", "Member"];
    const cleanRole = allowedRoles.includes(role) ? role : "ICT Student";

    if (!cleanName || !cleanEmail || !rawPassword) {
      return res.status(400).json({ error: "Name, email, and password are required." });
    }

    const store = await loadData();
    const exists = store.users.some((u) => u.email.toLowerCase() === cleanEmail);
    if (exists) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const newUser = {
      id: Date.now(),
      name: cleanName,
      email: cleanEmail,
      role: cleanRole,
      passwordHash: hashPassword(rawPassword),
      createdAt: new Date().toLocaleString()
    };

    store.users.push(newUser);
    await saveData(store);

    return res.status(201).json({
      message: "Account created!",
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch {
    return res.status(500).json({ error: "Failed to create account." });
  }
});

// POST /api/login - Authenticate existing member from any device/browser
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const cleanEmail = String(email || "").trim().toLowerCase();
    const rawPassword = String(password || "");

    if (!cleanEmail || !rawPassword) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    const store = await loadData();
    const user = store.users.find(
      (u) => u.email.toLowerCase() === cleanEmail && u.passwordHash === hashPassword(rawPassword)
    );

    if (!user) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    return res.json({
      message: "Login successful!",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch {
    return res.status(500).json({ error: "Login failed." });
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