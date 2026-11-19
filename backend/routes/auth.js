const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { OAuth2Client } = require("google-auth-library");
const axios = require("axios");
const pool = require("../db");
const auth = require("../middleware/auth");
const { logEvent, clientIp } = require("../services/securityLog");

const router = express.Router();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const mapDbError = (error) => {
  if (error?.code === "42P01") {
    return "Database tables not found. Run schema.sql first.";
  }
  if (error?.code === "3D000" || error?.code === "ECONNREFUSED") {
    return "Database not reachable. Check DATABASE_URL and PostgreSQL service.";
  }
  if (error?.code === "28P01") {
    return "Database authentication failed. Check DB username/password.";
  }
  return "Server error. Please try again.";
};

const safeUser = (row) => ({
  id: row.id,
  fullName: row.full_name,
  email: row.email,
  avatarUrl: row.avatar_url,
  jobTitle: row.job_title,
  company: row.company,
  createdAt: row.created_at,
});

const sendResetEmail = async (email, token) => {
  const resetUrl = `${process.env.FRONTEND_URL || "http://localhost:5173"}/reset-password?token=${token}`;
  const hasPlaceholderConfig =
    !process.env.SMTP_HOST ||
    !process.env.SMTP_USER ||
    !process.env.SMTP_PASS ||
    process.env.SMTP_USER.includes("your_email") ||
    process.env.SMTP_PASS.includes("your_app_password");

  if (hasPlaceholderConfig) {
    // Fallback for local development when SMTP is not configured.
    console.log(`[CloudSentinel] Reset link for ${email}: ${resetUrl}`);
    return { skipped: true, resetUrl };
  }

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || "false") === "true",
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: email,
    subject: "CloudSentinel password reset",
    text: `Reset your password: ${resetUrl}\nThis link expires in 1 hour.`,
    html: `<p>Reset your password by clicking the link below:</p><p><a href="${resetUrl}">${resetUrl}</a></p><p>This link expires in 1 hour.</p>`,
  });

  return { skipped: false };
};

router.post("/register", async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const exists = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (exists.rows.length) {
      return res.status(409).json({ error: "Email already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (full_name, email, password_hash) VALUES ($1,$2,$3) RETURNING *",
      [fullName, email, passwordHash]
    );

    const token = jwt.sign(
      { id: result.rows[0].id, email: result.rows[0].email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(201).json({ token, user: safeUser(result.rows[0]) });
  } catch (error) {
    return res.status(500).json({ error: mapDbError(error) });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const loginFailed = (reason, userId) => {
      logEvent({ level: "warn", event: "auth_login_failed", userId, ip: clientIp(req), detail: { account: String(email).toLowerCase().slice(0, 254), reason } });
      return res.status(401).json({ error: "Invalid credentials" });
    };
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!result.rows.length) return loginFailed("unknown_account");

    const valid = await bcrypt.compare(password, result.rows[0].password_hash);
    if (!valid) return loginFailed("bad_password", result.rows[0].id);

    const token = jwt.sign(
      { id: result.rows[0].id, email: result.rows[0].email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({ token, user: safeUser(result.rows[0]) });
  } catch (error) {
    return res.status(500).json({ error: mapDbError(error) });
  }
});

router.post("/google", async (req, res) => {
  try {
    const { idToken, accessToken } = req.body;
    if (!idToken && !accessToken) {
      return res.status(400).json({ error: "Google token is required" });
    }

    let email = null;
    let fullName = null;
    let avatarUrl = null;

    if (idToken) {
      if (!process.env.GOOGLE_CLIENT_ID) {
        return res.status(500).json({ error: "Google login is not configured on server" });
      }
      const ticket = await googleClient.verifyIdToken({
        idToken,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
      const payload = ticket.getPayload();
      if (!payload?.email) return res.status(400).json({ error: "Google account email is missing" });
      email = payload.email.toLowerCase();
      fullName = payload.name || email.split("@")[0];
      avatarUrl = payload.picture || null;
    } else {
      const profileRes = await axios.get("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const payload = profileRes.data || {};
      if (!payload?.email) return res.status(400).json({ error: "Google account email is missing" });
      email = String(payload.email).toLowerCase();
      fullName = payload.name || email.split("@")[0];
      avatarUrl = payload.picture || null;
    }

    let userRes = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!userRes.rows.length) {
      const randomHash = await bcrypt.hash(crypto.randomBytes(32).toString("hex"), 10);
      userRes = await pool.query(
        "INSERT INTO users (full_name, email, password_hash, avatar_url) VALUES ($1,$2,$3,$4) RETURNING *",
        [fullName, email, randomHash, avatarUrl]
      );
    }

    const user = userRes.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "7d" });
    return res.json({ token, user: safeUser(user) });
  } catch (error) {
    if (error?.response?.status === 401 || error?.message?.toLowerCase().includes("token")) {
      logEvent({ level: "warn", event: "auth_google_failed", ip: clientIp(req), detail: { reason: "invalid_token" } });
      return res.status(401).json({ error: "Invalid Google token" });
    }
    return res.status(500).json({ error: "Google login failed" });
  }
});

const allowedGithubRedirectUris = () => {
  const set = new Set();
  if (process.env.GITHUB_OAUTH_REDIRECT_URI) set.add(process.env.GITHUB_OAUTH_REDIRECT_URI.trim());
  const base = process.env.FRONTEND_URL?.replace(/\/$/, "");
  if (base) set.add(`${base}/github/callback`);
  ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://127.0.0.1:5174"].forEach((h) => {
    set.add(`${h}/github/callback`);
  });
  return set;
};

/** No JWT — GitHub redirects back asynchronously; requiring auth caused 401 mid-flow and prevented saving the token */
router.post("/github/exchange", async (req, res) => {
  try {
    const { code, redirect_uri: redirectUriBody } = req.body;
    if (!code) return res.status(400).json({ error: "GitHub authorization code is required" });
    if (!process.env.GITHUB_OAUTH_CLIENT_ID || !process.env.GITHUB_OAUTH_CLIENT_SECRET) {
      return res.status(500).json({ error: "GitHub OAuth is not configured on server" });
    }

    const fallbackRedirect =
      process.env.GITHUB_OAUTH_REDIRECT_URI?.trim() ||
      `${(process.env.FRONTEND_URL || "http://localhost:5173").replace(/\/$/, "")}/github/callback`;
    const redirect_uri = (typeof redirectUriBody === "string" && redirectUriBody.trim()
      ? redirectUriBody.trim()
      : fallbackRedirect);
    const allowed = allowedGithubRedirectUris();
    if (!allowed.has(redirect_uri)) {
      return res.status(400).json({ error: "Invalid redirect_uri for GitHub OAuth" });
    }

    const tokenRes = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: process.env.GITHUB_OAUTH_CLIENT_ID,
        client_secret: process.env.GITHUB_OAUTH_CLIENT_SECRET,
        code,
        redirect_uri,
      },
      {
        headers: { Accept: "application/json" },
      }
    );

    const accessToken = tokenRes.data?.access_token;
    if (!accessToken) return res.status(400).json({ error: "Failed to obtain GitHub access token" });

    const userRes = await axios.get("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    return res.json({
      success: true,
      accessToken,
      githubUser: {
        login: userRes.data?.login,
        avatarUrl: userRes.data?.avatar_url,
      },
    });
  } catch (error) {
    return res.status(500).json({ error: "GitHub OAuth exchange failed" });
  }
});

router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const userRes = await pool.query("SELECT id, email FROM users WHERE email = $1", [email]);
    // Return success-like response even when user is missing to avoid account enumeration.
    if (!userRes.rows.length) return res.json({ success: true, message: "If this email exists, reset instructions were sent." });

    const user = userRes.rows[0];
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await pool.query("DELETE FROM password_resets WHERE user_id = $1 OR expires_at < NOW() OR used = true", [user.id]);
    await pool.query(
      "INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, $3)",
      [user.id, token, expiresAt]
    );

    const emailResult = await sendResetEmail(user.email, token);
    return res.json({
      success: true,
      message: "If this email exists, reset instructions were sent.",
      devResetUrl: emailResult.skipped ? emailResult.resetUrl : undefined,
    });
  } catch (error) {
    if (error?.code === "EAUTH") {
      return res.status(500).json({ error: "SMTP authentication failed. Use a valid email/app password." });
    }
    return res.status(500).json({ error: "Forgot password failed. Check SMTP settings or use dev fallback." });
  }
});

router.post("/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: "Token and password are required" });
    if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

    const resetRes = await pool.query(
      "SELECT id, user_id FROM password_resets WHERE token = $1 AND used = false AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1",
      [token]
    );
    if (!resetRes.rows.length) return res.status(400).json({ error: "Invalid or expired reset token" });

    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [passwordHash, resetRes.rows[0].user_id]);
    await pool.query("UPDATE password_resets SET used = true WHERE id = $1", [resetRes.rows[0].id]);

    return res.json({ success: true, message: "Password reset successful" });
  } catch (error) {
    return res.status(500).json({ error: mapDbError(error) });
  }
});

router.get("/me", auth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    if (!result.rows.length) return res.status(404).json({ error: "User not found" });
    return res.json({ user: safeUser(result.rows[0]) });
  } catch (error) {
    return res.status(500).json({ error: "Server error. Please try again." });
  }
});

router.patch("/profile", auth, async (req, res) => {
  try {
    const { fullName, jobTitle, company } = req.body;
    const result = await pool.query(
      "UPDATE users SET full_name = COALESCE($1, full_name), job_title = COALESCE($2, job_title), company = COALESCE($3, company) WHERE id = $4 RETURNING *",
      [fullName, jobTitle, company, req.user.id]
    );
    return res.json({ user: safeUser(result.rows[0]) });
  } catch (error) {
    return res.status(500).json({ error: "Server error. Please try again." });
  }
});

module.exports = router;
