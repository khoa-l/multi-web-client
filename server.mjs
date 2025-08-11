// Reddit OAuth Backend Server - Multi-User ESM Version with Simplified Rate Limiting
// Run with: node server.mjs

import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// Reddit OAuth configuration
const REDDIT_CONFIG = {
  clientId: process.env.REDDIT_CLIENT_ID || "i3It5V7LR6o2s5BCTy-82A",
  clientSecret:
    process.env.REDDIT_CLIENT_SECRET || "6m2RxtVnEPLTVBePLSZULLxCiA_GJA",
  redirectUri:
    process.env.REDDIT_REDIRECT_URI || "http://localhost:3001/auth/callback",
  userAgent: "RedditClient/1.0 by YourUsername",
};

// Rate limiting configuration
const RATE_LIMIT = {
  maxRequests: 60, // Reddit allows 100 requests per minute per app
  windowMs: 60 * 1000, // 1 minute window
};

// In-memory stores
const sessions = new Map();
const userTokens = new Map();
const rateLimitData = {
  requests: [],
  lastReset: Date.now(),
};

// Rate limiting middleware
function checkRateLimit(req, res, next) {
  const now = Date.now();

  // Clean up old requests (older than window)
  rateLimitData.requests = rateLimitData.requests.filter(
    (timestamp) => now - timestamp < RATE_LIMIT.windowMs,
  );

  // Check if we're at the limit
  const currentRequests = rateLimitData.requests.length;

  if (currentRequests >= RATE_LIMIT.maxRequests) {
    const oldestRequest = Math.min(...rateLimitData.requests);
    const timeToWait = RATE_LIMIT.windowMs - (now - oldestRequest);

    return res.status(429).json({
      error: "Rate limit exceeded",
      message:
        "Too many requests to Reddit API. Please wait before making more requests.",
      rateLimitInfo: {
        current: currentRequests,
        max: RATE_LIMIT.maxRequests,
        windowMs: RATE_LIMIT.windowMs,
        retryAfter: Math.ceil(timeToWait / 1000),
      },
    });
  }

  // Record this request
  rateLimitData.requests.push(now);

  // Add rate limit info to response headers
  res.set("X-Rate-Limit-Current", currentRequests + 1);
  res.set("X-Rate-Limit-Max", RATE_LIMIT.maxRequests);
  res.set(
    "X-Rate-Limit-Remaining",
    RATE_LIMIT.maxRequests - currentRequests - 1,
  );

  next();
}

// Session middleware
function requireAuth(req, res, next) {
  const sessionId = req.headers["x-session-id"] || req.query.session;

  if (!sessionId || !sessions.has(sessionId)) {
    return res.status(401).json({ error: "Authentication required" });
  }

  const session = sessions.get(sessionId);
  if (!session || !userTokens.has(session.userId)) {
    return res.status(401).json({ error: "Invalid session" });
  }

  req.session = session;
  req.userToken = userTokens.get(session.userId);
  next();
}

// Middleware
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://localhost:3001",
      "http://127.0.0.1:3000",
      "http://127.0.0.1:3001",
      "http://192.168.1.79:3000",
      "http://192.168.1.79:3001",
    ],
    credentials: true,
    exposedHeaders: [
      "X-Rate-Limit-Current",
      "X-Rate-Limit-Max",
      "X-Rate-Limit-Remaining",
    ],
  }),
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve the HTML file
app.get("/", (req, res) => {
  res.sendFile(join(__dirname, "index.html"));
});

// Start OAuth flow
app.get("/auth/login", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");

  // Store state for validation - use 'created' consistently
  const tempSession = {
    state,
    created: Date.now(), // ← Fixed: now uses 'created'
    isTemp: true, // ← Added: mark as temporary
  };
  sessions.set(state, tempSession);

  const authUrl =
    "https://www.reddit.com/api/v1/authorize?" +
    new URLSearchParams({
      client_id: REDDIT_CONFIG.clientId,
      response_type: "code",
      state: state,
      redirect_uri: REDDIT_CONFIG.redirectUri,
      duration: "permanent",
      scope: "read identity mysubreddits",
    });

  res.redirect(authUrl);
});

// Handle OAuth callback
app.get("/auth/callback", async (req, res) => {
  const { code, state, error } = req.query;

  console.log("OAuth callback received:", {
    code: code?.substring(0, 10) + "...",
    state,
    error,
  });

  if (error) {
    console.error("OAuth error:", error);
    return res.redirect(`/?error=${encodeURIComponent(error)}`);
  }

  if (!code || !state || !sessions.has(state)) {
    console.error("Invalid request - missing code/state or state not found");
    return res.redirect("/?error=invalid_request");
  }

  try {
    console.log("Exchanging code for token...");

    // Exchange code for token
    const tokenResponse = await fetch(
      "https://www.reddit.com/api/v1/access_token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization:
            "Basic " +
            Buffer.from(
              REDDIT_CONFIG.clientId + ":" + REDDIT_CONFIG.clientSecret,
            ).toString("base64"),
          "User-Agent": REDDIT_CONFIG.userAgent,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code,
          redirect_uri: REDDIT_CONFIG.redirectUri,
        }),
      },
    );

    const tokenData = await tokenResponse.json();
    console.log("Token response status:", tokenResponse.status);

    if (!tokenResponse.ok) {
      console.error("Reddit token error:", tokenData);
      return res.redirect(
        `/?error=token_exchange_failed&details=${encodeURIComponent(
          JSON.stringify(tokenData),
        )}`,
      );
    }

    console.log("Token exchange successful, getting user info...");

    // Get user info
    let userResponse = await fetch("https://oauth.reddit.com/api/v1/me", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        "User-Agent": REDDIT_CONFIG.userAgent,
      },
    });

    let userData = await userResponse.json();

    if (!userResponse.ok && userResponse.status === 403) {
      userResponse = await fetch("https://oauth.reddit.com/user/me", {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          "User-Agent": REDDIT_CONFIG.userAgent,
        },
      });
      userData = await userResponse.json();
    }

    if (!userResponse.ok) {
      console.error("User info error:", userData);
      return res.redirect("/?error=user_info_failed");
    }

    console.log("User authenticated:", userData.name);

    // Create session
    const sessionId = crypto.randomBytes(32).toString("hex");
    const userId = userData.id;

    // Store user token
    userTokens.set(userId, {
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      expires_at: Date.now() + tokenData.expires_in * 1000,
      user: userData,
    });

    // Create session
    sessions.set(sessionId, {
      userId: userId,
      username: userData.name,
      created: Date.now(),
    });

    // Clean up temp session
    sessions.delete(state);

    console.log(`Session created for user: ${userData.name}`);

    // Redirect with session
    res.redirect(
      `/?session=${sessionId}&username=${encodeURIComponent(userData.name)}`,
    );
  } catch (error) {
    console.error("OAuth callback error:", error);
    res.redirect("/?error=server_error");
  }
});

// Get current user info
app.get("/auth/me", requireAuth, (req, res) => {
  const userToken = userTokens.get(req.session.userId);
  res.json({
    session: req.session,
    user: userToken.user,
  });
});

// Logout
app.post("/auth/logout", requireAuth, (req, res) => {
  const sessionId = req.headers["x-session-id"];
  const username = req.session.username;
  sessions.delete(sessionId);
  console.log(`User ${username} logged out`);
  res.json({ success: true });
});

// Get rate limit status
app.get("/api/rate-limit", (req, res) => {
  const now = Date.now();

  // Clean up old requests
  rateLimitData.requests = rateLimitData.requests.filter(
    (timestamp) => now - timestamp < RATE_LIMIT.windowMs,
  );

  const currentRequests = rateLimitData.requests.length;
  const remaining = RATE_LIMIT.maxRequests - currentRequests;

  res.json({
    current: currentRequests,
    max: RATE_LIMIT.maxRequests,
    remaining: remaining,
    windowMs: RATE_LIMIT.windowMs,
  });
});

// Proxy Reddit API calls with rate limiting
app.get("/api/reddit/*", requireAuth, checkRateLimit, async (req, res) => {
  const redditPath = req.params[0];
  const userToken = req.userToken;

  try {
    const redditUrl = `https://oauth.reddit.com/${redditPath}`;

    // Add query parameters from request
    const url = new URL(redditUrl);
    for (const [key, value] of Object.entries(req.query)) {
      url.searchParams.append(key, value);
    }

    console.log(
      `Proxying Reddit API call for user ${
        req.session.username
      }: ${url.toString()}`,
    );

    const response = await fetch(url.toString(), {
      headers: {
        Authorization: `Bearer ${userToken.access_token}`,
        "User-Agent": REDDIT_CONFIG.userAgent,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("Reddit API error:", response.status, data);
      return res.status(response.status).json(data);
    }

    res.json(data);
  } catch (error) {
    console.error("Reddit API proxy error:", error);
    res.status(500).json({
      error: "Proxy error",
      message: error.message,
    });
  }
});

// Health check
app.get("/health", (req, res) => {
  const now = Date.now();
  rateLimitData.requests = rateLimitData.requests.filter(
    (timestamp) => now - timestamp < RATE_LIMIT.windowMs,
  );

  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    activeSessions: sessions.size,
    activeUsers: userTokens.size,
    rateLimit: {
      current: rateLimitData.requests.length,
      max: RATE_LIMIT.maxRequests,
      remaining: RATE_LIMIT.maxRequests - rateLimitData.requests.length,
    },
  });
});

// Admin endpoint to see active sessions (remove in production)
app.get("/admin/sessions", (req, res) => {
  try {
    const sessionList = Array.from(sessions.entries()).map(([id, session]) => {
      // Safely handle potentially invalid timestamps
      let createdISO = "Invalid Date";
      try {
        if (session.created && typeof session.created === "number") {
          createdISO = new Date(session.created).toISOString();
        } else if (session.created) {
          createdISO = new Date(session.created).toISOString();
        }
      } catch (dateError) {
        createdISO = `Invalid: ${session.created}`;
      }

      return {
        id: id.substring(0, 8) + "...",
        username: session.username || "unknown",
        created: createdISO,
        userId: session.userId || "unknown",
        rawCreated: session.created, // For debugging
      };
    });

    res.json({
      sessions: sessionList,
      totalSessions: sessions.size,
      totalUsers: userTokens.size,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Admin endpoint error:", error);
    res.status(500).json({
      error: "Admin endpoint failed",
      message: error.message,
      sessionsCount: sessions.size,
    });
  }
});

// Error handling
app.use((error, req, res, next) => {
  console.error("Server error:", error);
  res.status(500).json({
    error: "Internal server error",
    message: error.message,
  });
});

app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// Clean up invalid sessions on startup
function cleanupSessions() {
  let cleaned = 0;
  for (const [sessionId, session] of sessions.entries()) {
    // Remove sessions with invalid timestamps or temp sessions older than 1 hour
    if (
      !session.created ||
      (session.isTemp && Date.now() - session.created > 3600000) ||
      typeof session.created !== "number"
    ) {
      sessions.delete(sessionId);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    console.log(`Cleaned up ${cleaned} invalid sessions`);
  }
}

// Run cleanup on server start and periodically
cleanupSessions();
setInterval(cleanupSessions, 300000); // Every 5 minutes

app.listen(PORT, () => {
  console.log(`🚀 Reddit OAuth Backend Server (ESM) running on port ${PORT}`);
  console.log(`📍 Server URL: http://localhost:${PORT}`);
  console.log(`🔧 OAuth Redirect URI: ${REDDIT_CONFIG.redirectUri}`);
  console.log(`👥 Multi-user session-based authentication enabled`);
  console.log(
    `⚡ Rate limiting: ${RATE_LIMIT.maxRequests} requests per minute`,
  );
  console.log(`\n📖 API Endpoints:`);
  console.log(`   GET /auth/login - Start OAuth flow`);
  console.log(`   GET /auth/callback - OAuth callback`);
  console.log(`   GET /auth/me - Current user info`);
  console.log(`   POST /auth/logout - Logout`);
  console.log(`   GET /api/reddit/* - Proxy Reddit API calls`);
  console.log(`   GET /api/rate-limit - Check rate limit status`);
  console.log(`   GET /admin/sessions - View active sessions`);
  console.log(`\n🌐 Open in browser: http://localhost:${PORT}`);
});

export default app;
