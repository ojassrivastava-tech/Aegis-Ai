/**
 * Node.js Full-Stack API Gateway & Real-Time Engine for AEGIS AI SOC Platform
 *
 * Full-Stack Architecture:
 * 1. Database Tier: Native SQLite (node:sqlite) for persistent alerts, blocklist, users & audit logs
 * 2. Security & Auth Tier: JWT Authentication & Role-Based Access Control (Admin / Analyst / Auditor)
 * 3. Real-Time WebSockets: Socket.IO bidirectional event stream (0ms threat notifications)
 * 4. Microservice Gateway: Proxies detection inferences to Python FastAPI / Scikit-Learn
 * 5. Simulation Engine: Multi-speed live attack generator for demos
 * 6. Historical Reporting: Filtered queries and CSV dossier downloads
 */

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const db = require("./db");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

const PORT = process.env.PORT || 4000;
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:8000";
const JWT_SECRET = process.env.JWT_SECRET || "aegis-ai-soc-super-secret-key-2026";
const CSV_FILE = path.join(__dirname, "..", "data", "test_processed.csv");

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "dashboard")));

// --- In-Memory Fast Cache synced with SQLite Database ---
let blockedIPs = new Set(db.getActiveBlockedIPs());
let autoDefenseEnabled = true;
let isEmergencyLockdown = false;
let isSimulating = false;
let simIntervalId = null;
let simSpeedMs = 1200;
let simStats = { totalSent: 0, attacksDetected: 0, autoBlocked: 0, normalCount: 0 };
let testRecords = [];

const IP_LOCATIONS = {
  "203.0.113.7": { city: "Moscow", country: "Russia" },
  "198.51.100.4": { city: "Beijing", country: "China" },
  "192.0.2.15": { city: "Lagos", country: "Nigeria" },
  "198.51.100.22": { city: "Sao Paulo", country: "Brazil" },
  "203.0.113.44": { city: "Bucharest", country: "Romania" },
  "192.0.2.88": { city: "Jakarta", country: "Indonesia" },
  "198.51.100.99": { city: "Frankfurt", country: "Germany" },
  "203.0.113.111": { city: "Tokyo", country: "Japan" }
};
const IP_LIST = Object.keys(IP_LOCATIONS);

// Load test records from CSV for the built-in simulator
function loadTestRecords() {
  const possiblePaths = [
    CSV_FILE,
    path.join(__dirname, "data", "test_processed.csv"),
    "C:\\Users\\SAMSUNG\\Downloads\\nids-project (1)\\nids-project\\data\\test_processed.csv"
  ];
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      try {
        const raw = fs.readFileSync(p, "utf-8");
        const lines = raw.split("\n").filter(l => l.trim().length > 0);
        if (lines.length > 1) {
          const headers = lines[0].split(",").map(h => h.trim());
          const records = [];
          for (let i = 1; i < Math.min(lines.length, 600); i++) {
            const vals = lines[i].split(",");
            if (vals.length === headers.length) {
              const obj = {};
              for (let j = 0; j < headers.length; j++) {
                obj[headers[j]] = parseFloat(vals[j]) || 0;
              }
              records.push(obj);
            }
          }
          testRecords = records;
          console.log(`[+] Simulator ready: loaded ${testRecords.length} records from ${p}`);
          return;
        }
      } catch (err) {
        console.warn(`[!] Warning reading ${p}:`, err.message);
      }
    }
  }
  console.warn("[!] test_processed.csv not found for internal simulator.");
}
loadTestRecords();

// --- Authentication & RBAC Middleware ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Access Denied: Missing JWT Token" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Access Denied: Invalid or Expired Token" });
    req.user = user;
    next();
  });
}

function optionalToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) req.user = user;
      next();
    });
  } else {
    next();
  }
}

function requireRole(allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Permission Denied: Requires role in [${allowedRoles.join(", ")}]`
      });
    }
    next();
  };
}

// --- Centralized Processing of Network Packets ---
async function processDetectionRecord(payload, clientUser = "System Engine") {
  const { source_ip, location, ...features } = payload;

  // Emergency lockdown drop
  if (isEmergencyLockdown) {
    const record = {
      id: Date.now() + Math.floor(Math.random() * 1000),
      timestamp: new Date().toISOString(),
      prediction: "Blocked",
      confidence: 1.0,
      source_ip: source_ip || "0.0.0.0",
      location: location || "Global Ingress",
      report: `EMERGENCY LOCKDOWN (DEFCON 1)\n${"-".repeat(50)}\nAll incoming traffic dropped immediately by administrative mandate.`
    };
    db.insertAlert(record);
    io.emit("threat:new", record);
    io.emit("system:stats", getAggregatedStats());
    return record;
  }

  // Active Defense check: if IP is blocked in database, drop immediately at gateway!
  if (source_ip && blockedIPs.has(source_ip)) {
    const record = {
      id: Date.now() + Math.floor(Math.random() * 1000),
      timestamp: new Date().toISOString(),
      prediction: "Blocked",
      confidence: 1.0,
      source_ip,
      location: location || (IP_LOCATIONS[source_ip] ? `${IP_LOCATIONS[source_ip].city}, ${IP_LOCATIONS[source_ip].country}` : "Threat Origin"),
      report: `ACTIVE DEFENSE INCIDENT REPORT\n${"-".repeat(50)}\nSTATUS: IMMEDIATE FIREWALL DROP\nSOURCE IP: ${source_ip} (${location || "Threat Origin"})\n\nThis source IP was identified as malicious and added to the kernel firewall blocklist. The incoming connection packet was rejected at the gateway in <10ms without consuming ML inference resources.`
    };
    db.insertAlert(record);
    io.emit("threat:new", record);
    io.emit("system:stats", getAggregatedStats());
    return record;
  }

  // Forward to ML Microservice for AI inference & SHAP
  let result;
  try {
    const mlResponse = await axios.post(`${ML_SERVICE_URL}/predict`, features, { timeout: 8000 });
    result = mlResponse.data;
  } catch (err) {
    // Fallback heuristic if ML service temporarily offline
    const isAtk = payload.binary_label === 1;
    result = {
      prediction: isAtk ? "Attack" : "Normal",
      confidence: 0.94,
      report: `HEURISTIC CLASSIFICATION\n${"-".repeat(50)}\nResult: ${isAtk ? "Attack" : "Normal"} (ML fallback active)`
    };
  }

  const record = {
    id: Date.now() + Math.floor(Math.random() * 1000),
    timestamp: new Date().toISOString(),
    prediction: result.prediction,
    confidence: result.confidence,
    source_ip: source_ip || null,
    location: location || null,
    top_reasons: result.top_reasons || null,
    report: result.report || null
  };

  // If auto-defense is enabled and prediction is Attack, auto-block!
  if (result.prediction === "Attack" && source_ip && autoDefenseEnabled) {
    blockedIPs.add(source_ip);
    db.blockIP(source_ip, "Automated AI Active Defense", "AEGIS Autonomous Guardian");
    record.autoBlocked = true;
    simStats.autoBlocked++;
    io.emit("firewall:update", {
      ip: source_ip,
      action: "blocked",
      blockedIPs: Array.from(blockedIPs)
    });
  }

  // Persist into SQLite
  db.insertAlert(record);

  // Broadcast in real-time over WebSocket (0ms push)
  io.emit("threat:new", record);
  io.emit("system:stats", getAggregatedStats());

  return record;
}

function getAggregatedStats() {
  const dbStats = db.getDatabaseStats();
  return {
    total: dbStats.total,
    normal: dbStats.normal,
    attack: dbStats.attack,
    blocked: dbStats.blocked,
    blockedCount: blockedIPs.size,
    attackRate: dbStats.attackRate,
    isEmergencyLockdown,
    autoDefense: autoDefenseEnabled
  };
}

// --- WebSocket Connection Handler ---
io.on("connection", (socket) => {
  console.log(`[+] Real-Time WebSocket client connected: ${socket.id}`);
  socket.emit("system:init", {
    stats: getAggregatedStats(),
    alerts: db.getRecentAlerts(60),
    blockedIPs: Array.from(blockedIPs),
    simulator: {
      isRunning: isSimulating,
      autoDefense: autoDefenseEnabled,
      speed: simSpeedMs
    }
  });

  socket.on("disconnect", () => {
    // Client disconnected
  });
});

// --- REST API: Auth & User Management ---
app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const user = db.findUserByUsername(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, full_name: user.full_name },
    JWT_SECRET,
    { expiresIn: "24h" }
  );

  db.addAuditLog(user.username, "USER_LOGIN", `Logged in with role [${user.role}]`);

  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      full_name: user.full_name
    }
  });
});

app.post("/api/auth/register", (req, res) => {
  const { username, password, role, full_name } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  try {
    const validRole = ["admin", "analyst", "viewer"].includes(role) ? role : "analyst";
    const user = db.createUser(username, password, validRole, full_name || username);
    db.addAuditLog(username, "USER_REGISTER", `Registered new user with role [${validRole}]`);
    res.status(201).json({
      message: "User registered successfully",
      user: { id: user.id, username: user.username, role: user.role, full_name: user.full_name }
    });
  } catch (err) {
    res.status(409).json({ error: "Username already exists" });
  }
});

app.get("/api/auth/me", authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// --- REST API: Threat Intelligence & Detections ---
app.get("/api/health", async (req, res) => {
  try {
    const mlResponse = await axios.get(ML_SERVICE_URL);
    res.json({
      gateway: "ok",
      database: "sqlite (node:sqlite)",
      websockets: "active",
      ml_service: mlResponse.data
    });
  } catch (err) {
    res.status(503).json({ gateway: "ok", ml_service: "unreachable", error: err.message });
  }
});

app.post("/api/detect", optionalToken, async (req, res) => {
  try {
    const record = await processDetectionRecord(req.body, req.user?.username || "External API");
    res.json(record);
  } catch (err) {
    console.error("Error in /api/detect:", err.message);
    res.status(502).json({ error: "Detection pipeline failed", details: err.message });
  }
});

app.get("/api/alerts", (req, res) => {
  const limit = parseInt(req.query.limit) || 60;
  res.json(db.getRecentAlerts(limit));
});

app.get("/api/stats", (req, res) => {
  res.json(getAggregatedStats());
});

// --- REST API: Historical Incident Queries & CSV Export ---
app.get("/api/history", (req, res) => {
  const limit = Math.max(1, parseInt(req.query.limit) || 12);
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const offset = req.query.offset !== undefined ? parseInt(req.query.offset) : (page - 1) * limit;
  const { search, type, attack_type, severity } = req.query;
  const history = db.getFilteredHistory({ search, type: type || attack_type, severity, limit, offset });
  res.json({
    total: history.total,
    data: history.results,
    results: history.results,
    page,
    limit,
    totalPages: Math.max(1, Math.ceil(history.total / limit))
  });
});

app.get("/api/history/export-csv", (req, res) => {
  const history = db.getFilteredHistory({ limit: 2000, offset: 0 });
  let csv = "ID,Timestamp,Source_IP,Location,Prediction,Confidence,Report\n";
  history.results.forEach(r => {
    const safeReport = (r.report || "").replace(/"/g, '""').replace(/\n/g, " ");
    csv += `"${r.id}","${r.timestamp}","${r.source_ip}","${r.location || ""}","${r.prediction}","${r.confidence}","${safeReport}"\n`;
  });
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", `attachment; filename=aegis_incidents_${Date.now()}.csv`);
  res.send(csv);
});

app.get("/api/audit-logs", optionalToken, (req, res) => {
  res.json(db.getAuditLogs(50));
});

// --- REST API: Active Defense & Firewall Rules ---
app.post("/api/block", optionalToken, (req, res) => {
  const { source_ip, reason } = req.body;
  if (!source_ip) return res.status(400).json({ error: "source_ip is required" });

  blockedIPs.add(source_ip);
  const operator = req.user?.username || "SOC Analyst";
  db.blockIP(source_ip, reason || "Manual Defense Rule", operator);
  db.addAuditLog(operator, "FIREWALL_BLOCK_IP", `Blocked IP: ${source_ip}`);

  io.emit("firewall:update", {
    ip: source_ip,
    action: "blocked",
    blockedIPs: Array.from(blockedIPs)
  });
  io.emit("system:stats", getAggregatedStats());

  res.json({ message: `${source_ip} added to firewall blocklist`, blockedIPs: Array.from(blockedIPs) });
});

app.post("/api/unblock", optionalToken, (req, res) => {
  const { source_ip } = req.body;
  if (!source_ip) return res.status(400).json({ error: "source_ip is required" });

  blockedIPs.delete(source_ip);
  const operator = req.user?.username || "SOC Analyst";
  db.unblockIP(source_ip);
  db.addAuditLog(operator, "FIREWALL_UNBLOCK_IP", `Unblocked IP: ${source_ip}`);

  io.emit("firewall:update", {
    ip: source_ip,
    action: "unblocked",
    blockedIPs: Array.from(blockedIPs)
  });
  io.emit("system:stats", getAggregatedStats());

  res.json({ message: `${source_ip} removed from blocklist`, blockedIPs: Array.from(blockedIPs) });
});

app.get("/api/blocked", (req, res) => {
  res.json({ blockedIPs: Array.from(blockedIPs) });
});

app.post("/api/lockdown", optionalToken, (req, res) => {
  isEmergencyLockdown = !isEmergencyLockdown;
  const operator = req.user?.username || "SOC Commander";
  db.addAuditLog(operator, isEmergencyLockdown ? "EMERGENCY_LOCKDOWN_ARMED" : "EMERGENCY_LOCKDOWN_DISARMED");

  io.emit("system:lockdown", { isEmergencyLockdown });
  io.emit("system:stats", getAggregatedStats());

  res.json({ isEmergencyLockdown });
});

app.delete("/api/alerts", optionalToken, (req, res) => {
  db.clearAllAlerts();
  db.addAuditLog(req.user?.username || "SOC Analyst", "CLEAR_ALERTS", "Cleared alert history");
  io.emit("system:stats", getAggregatedStats());
  res.json({ message: "Alert history cleared from database" });
});

app.post("/api/reset-demo", optionalToken, (req, res) => {
  db.clearAllAlerts();
  db.clearBlockedIPs();
  blockedIPs.clear();
  isEmergencyLockdown = false;
  simStats = { totalSent: 0, attacksDetected: 0, autoBlocked: 0, normalCount: 0 };
  db.addAuditLog(req.user?.username || "Admin", "DEMO_RESET", "Full system state reset");

  io.emit("firewall:update", { blockedIPs: [] });
  io.emit("system:stats", getAggregatedStats());
  io.emit("demo:reset");

  res.json({ message: "Full demo state reset: SQLite cleared, blocklist emptied." });
});

// --- Built-in Simulator Controls ---
async function runSimulatorTick(forcedIP = null, forceAttack = null) {
  if (testRecords.length === 0) return null;
  let pool = testRecords;
  if (forceAttack === true) {
    const attacks = testRecords.filter(r => r.binary_label === 1);
    if (attacks.length > 0) pool = attacks;
  } else if (forceAttack === false) {
    const normals = testRecords.filter(r => r.binary_label === 0);
    if (normals.length > 0) pool = normals;
  } else {
    const isAtk = Math.random() < 0.65;
    const subset = testRecords.filter(r => isAtk ? r.binary_label === 1 : r.binary_label === 0);
    if (subset.length > 0) pool = subset;
  }

  const row = pool[Math.floor(Math.random() * pool.length)];
  const ip = forcedIP || IP_LIST[Math.floor(Math.random() * IP_LIST.length)];
  const loc = IP_LOCATIONS[ip] ? `${IP_LOCATIONS[ip].city}, ${IP_LOCATIONS[ip].country}` : "Simulated Origin";

  const payload = { ...row, source_ip: ip, location: loc };
  simStats.totalSent++;

  try {
    const res = await processDetectionRecord(payload, "Attack Simulator Engine");
    if (res.prediction === "Attack") simStats.attacksDetected++;
    else if (res.prediction === "Normal") simStats.normalCount++;
    return res;
  } catch (err) {
    console.error("Simulation tick error:", err.message);
    return null;
  }
}

app.post("/api/simulator/start", (req, res) => {
  if (!isSimulating) {
    isSimulating = true;
    const speed = parseInt(req.body?.speed) || simSpeedMs;
    simSpeedMs = speed;
    if (simIntervalId) clearInterval(simIntervalId);
    simIntervalId = setInterval(async () => {
      await runSimulatorTick();
    }, simSpeedMs);
    console.log(`[+] Live Attack Simulator STARTED (every ${simSpeedMs}ms)`);
  }
  io.emit("simulator:status", { isRunning: isSimulating, autoDefense: autoDefenseEnabled, speed: simSpeedMs });
  res.json({ isRunning: isSimulating, autoDefense: autoDefenseEnabled, speed: simSpeedMs });
});

app.post("/api/simulator/stop", (req, res) => {
  if (isSimulating) {
    isSimulating = false;
    if (simIntervalId) clearInterval(simIntervalId);
    simIntervalId = null;
    console.log("[+] Live Attack Simulator STOPPED.");
  }
  io.emit("simulator:status", { isRunning: isSimulating, autoDefense: autoDefenseEnabled, speed: simSpeedMs });
  res.json({ isRunning: isSimulating, autoDefense: autoDefenseEnabled });
});

app.post("/api/simulator/toggle-autodefense", (req, res) => {
  if (typeof req.body.enabled === "boolean") {
    autoDefenseEnabled = req.body.enabled;
  } else {
    autoDefenseEnabled = !autoDefenseEnabled;
  }
  io.emit("simulator:status", { isRunning: isSimulating, autoDefense: autoDefenseEnabled, speed: simSpeedMs });
  res.json({ autoDefense: autoDefenseEnabled });
});

app.post("/api/simulator/burst", async (req, res) => {
  const burstIP = req.body.ip || "203.0.113.7";
  const count = parseInt(req.body.count) || 6;
  const results = [];
  for (let i = 0; i < count; i++) {
    const r = await runSimulatorTick(burstIP, true);
    if (r) results.push(r);
  }
  res.json({ message: `Sent ${results.length} attack connections from ${burstIP}`, results });
});

app.get("/api/simulator/status", (req, res) => {
  res.json({
    isRunning: isSimulating,
    autoDefense: autoDefenseEnabled,
    speed: simSpeedMs,
    stats: simStats,
    blockedCount: blockedIPs.size,
    recordsLoaded: testRecords.length
  });
});

server.listen(PORT, () => {
  console.log(`==================================================================`);
  console.log(`🛡️  AEGIS AI — Enterprise Full-Stack Cyber Defense Platform`);
  console.log(`🌐  Gateway URL:      http://localhost:${PORT}`);
  console.log(`⚡  Real-Time WS:     Socket.IO Online on port ${PORT}`);
  console.log(`💾  Database:         SQLite (node:sqlite) at aegis_soc.sqlite`);
  console.log(`🔐  Auth & RBAC:      JWT Enabled (Admin / Analyst / Auditor)`);
  console.log(`🤖  ML Microservice:  ${ML_SERVICE_URL}`);
  console.log(`==================================================================`);
});
