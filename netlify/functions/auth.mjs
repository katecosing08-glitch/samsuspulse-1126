import crypto from "node:crypto";

export function hashPassword(password) {
  return crypto.createHash("sha256").update(String(password)).digest("hex");
}

export function canDeletePost(post, requester = {}) {
  const role = String(requester.role || "").toLowerCase();
  if (role === "admin" || role === "moderator") {
    return true;
  }
  const reqName = String(requester.name || requester.username || "").trim().toLowerCase();
  const postAuthor = String(post.author || "").trim().toLowerCase();
  return Boolean(reqName && postAuthor && reqName === postAuthor);
}
