import express, { json, static as serveStatic } from "express";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { readFile, writeFile } from "fs/promises";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DATA_FILE = join(__dirname, "data.json");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(json());
app.use(serveStatic(join(__dirname, "public")));

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

async function loadData() {
  try {
    const raw = await readFile(DATA_FILE, "utf-8");
    const parsed = JSON.parse(raw);
    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      posts: Array.isArray(parsed.posts) ? parsed.posts : defaultData.posts
    };
  } catch (err) {
    if (err.code === "ENOENT") {
      await saveData(defaultData);
      return { ...defaultData, users: [...defaultData.users], posts: [...defaultData.posts] };
    }
    throw err;
  }
}

async function saveData(data) {
  await writeFile(DATA_FILE, JSON.stringify(data, null, 2), "utf-8");
}

// POST /api/signup - Register a new user account
app.post("/api/signup", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    const store = await loadData();
    const existing = store.users.find(
      (u) => u.email.toLowerCase() === String(email).toLowerCase()
    );
    if (existing) {
      return res.status(409).json({ error: "Account with that email already exists." });
    }

    const newUser = {
      id: store.users.length + 1,
      name: name || email.split("@")[0],
      username: name || email.split("@")[0],
      email: String(email).trim(),
      password,
      role: role || "Member"
    };

    store.users.push(newUser);
    await saveData(store);

    return res.status(201).json({
      message: "Account created successfully!",
      user: {
        id: newUser.id,
        name: newUser.name,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (err) {
    return res.status(500).json({ error: "Failed to save user account." });
  }
});

// POST /api/login - Authenticate user credentials
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const store = await loadData();

    const user = store.users.find(
      (u) =>
        u.email.toLowerCase() === String(email).toLowerCase() &&
        u.password === password
    );

    if (!user) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    return res.json({
      message: "Login successful!",
      user: {
        id: user.id,
        name: user.name,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    return res.status(500).json({ error: "Failed to process login." });
  }
});

// GET /api/posts - Retrieve all live board posts
app.get("/api/posts", async (req, res) => {
  try {
    const store = await loadData();
    return res.json({ posts: store.posts });
  } catch (err) {
    return res.status(500).json({ error: "Failed to load posts." });
  }
});

// POST /api/posts - Publish a new post to the live board
app.post("/api/posts", async (req, res) => {
  try {
    const { author, role, title, content } = req.body;

    if (!title || !content) {
      return res.status(400).json({ error: "Title and content are required." });
    }

    const store = await loadData();
    const newPost = {
      id: store.posts.length + 1,
      author: author || "Member",
      role: role || "Member",
      title,
      content,
      timestamp: new Date().toLocaleString()
    };

    store.posts.unshift(newPost);
    await saveData(store);

    return res.status(201).json({ message: "Post published!", post: newPost });
  } catch (err) {
    return res.status(500).json({ error: "Failed to publish post." });
  }
});

app.listen(PORT, () => {
  console.log(`SamsusPulse Express server running on http://localhost:${PORT}`);
});
