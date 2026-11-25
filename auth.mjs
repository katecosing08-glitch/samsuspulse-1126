import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

export default async (req) => {
  const store = getStore("nexuspulse-db");

  // Handle GET requests (Fetch public dashboard feed)
  if (req.method === "GET") {
    const posts = (await store.get("posts", { type: "json" })) || [
      {
        id: 1,
        author: "System Admin",
        role: "Project Lead",
        title: "Welcome to NexusPulse 1126!",
        content: "This full-stack workspace runs on Netlify Functions & Blobs. Sign up to post your own project updates!",
        timestamp: new Date().toLocaleDateString()
      }
    ];
    return Response.json({ posts });
  }

  // Handle POST requests (Signup, Login, Create Post)
  if (req.method === "POST") {
    try {
      const body = await req.json();
      const { action } = body;

      // 1. SIGN UP
      if (action === "signup") {
        const { name, email, password, role } = body;
        if (!name || !email || !password) {
          return Response.json({ error: "All fields are required." }, { status: 400 });
        }

        const users = (await store.get("users", { type: "json" })) || {};
        const cleanEmail = email.toLowerCase().trim();

        if (users[cleanEmail]) {
          return Response.json({ error: "An account with this email already exists." }, { status: 409 });
        }

        users[cleanEmail] = {
          name: name.trim(),
          email: cleanEmail,
          role: role || "Member",
          passwordHash: hashPassword(password),
          joined: new Date().toLocaleDateString()
        };

        await store.setJSON("users", users);
        return Response.json({
          message: "Account created!",
          user: { name: users[cleanEmail].name, email: cleanEmail, role: users[cleanEmail].role }
        });
      }

      // 2. LOGIN
      if (action === "login") {
        const { email, password } = body;
        const users = (await store.get("users", { type: "json" })) || {};
        const cleanEmail = (email || "").toLowerCase().trim();
        const user = users[cleanEmail];

        if (!user || user.passwordHash !== hashPassword(password || "")) {
          return Response.json({ error: "Invalid email or password." }, { status: 401 });
        }

        return Response.json({
          message: "Login successful!",
          user: { name: user.name, email: user.email, role: user.role }
        });
      }

      // 3. ADD DASHBOARD POST
      if (action === "add_post") {
        const { author, role, title, content } = body;
        if (!title || !content) {
          return Response.json({ error: "Title and message are required." }, { status: 400 });
        }

        const posts = (await store.get("posts", { type: "json" })) || [];
        const newPost = {
          id: Date.now(),
          author,
          role,
          title: title.trim(),
          content: content.trim(),
          timestamp: new Date().toLocaleString([], { dateStyle: "medium", timeStyle: "short" })
        };

        posts.unshift(newPost);
        await store.setJSON("posts", posts.slice(0, 50)); // Keep latest 50 posts
        return Response.json({ posts });
      }

      return Response.json({ error: "Invalid action." }, { status: 400 });
    } catch (err) {
      return Response.json({ error: "Server error: " + err.message }, { status: 500 });
    }
  }

  return new Response("Method not allowed", { status: 405 });
};