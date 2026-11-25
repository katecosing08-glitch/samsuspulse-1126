const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse incoming JSON payloads
app.use(express.json());

// Serve static frontend files from public/
app.use(express.static(path.join(__dirname, "public")));

// In-memory data stores for demo/class requirements
const users = [];
let posts = [
  {
    id: 1,
    author: "Admin",
    role: "Admin",
    title: "Welcome to SamsusPulse",
    content: "Express.js backend is active and serving live board updates.",
    timestamp: new Date().toLocaleString()
  }
];

// POST /api/signup - Register a new user account
app.post("/api/signup", (req, res) => {
  const { name, email, password, role } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const existing = users.find((u) => u.email.toLowerCase() === email.toLowerCase());
  if (existing) {
    return res.status(409).json({ error: "Account with that email already exists." });
  }

  const newUser = {
    id: users.length + 1,
    name: name || email.split("@")[0],
    username: name || email.split("@")[0],
    email,
    password,
    role: role || "Member"
  };

  users.push(newUser);
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
});

// POST /api/login - Authenticate user credentials
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  const user = users.find(
    (u) => u.email.toLowerCase() === String(email).toLowerCase() && u.password === password
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
});

// GET /api/posts - Retrieve all live board posts
app.get("/api/posts", (req, res) => {
  return res.json({ posts });
});

// POST /api/posts - Publish a new post to the live board
app.post("/api/posts", (req, res) => {
  const { author, role, title, content } = req.body;

  if (!title || !content) {
    return res.status(400).json({ error: "Title and content are required." });
  }

  const newPost = {
    id: posts.length + 1,
    author: author || "Member",
    role: role || "Member",
    title,
    content,
    timestamp: new Date().toLocaleString()
  };

  posts.unshift(newPost);
  return res.status(201).json({ message: "Post published!", post: newPost });
});

app.listen(PORT, () => {
  console.log(`SamsusPulse Express server running on http://localhost:${PORT}`);
});
