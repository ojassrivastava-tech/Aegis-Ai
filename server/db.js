/**
 * Database Module for AEGIS AI SOC Platform
 * Uses Node.js native SQLite (node:sqlite) for zero-dependency, ultra-fast persistence.
 */

const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'aegis_soc.sqlite');
const db = new DatabaseSync(DB_PATH);

// Initialize Tables
function initDatabase() {
  // 1. Users Table (RBAC: admin, analyst, viewer)
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'analyst',
      full_name TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // 2. Alerts Table (Persistent Threat Records)
  db.exec(`
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY,
      timestamp TEXT NOT NULL,
      source_ip TEXT NOT NULL,
      location TEXT,
      prediction TEXT NOT NULL,
      confidence REAL DEFAULT 0.0,
      report TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip);
    CREATE INDEX IF NOT EXISTS idx_alerts_prediction ON alerts(prediction);
    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
  `);

  // 3. Firewall Blocklist Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS blocked_ips (
      ip TEXT PRIMARY KEY,
      reason TEXT,
      blocked_by TEXT DEFAULT 'SYSTEM',
      blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      active INTEGER DEFAULT 1
    );
  `);

  // 4. Audit Logs Table (SOC Compliance)
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      action TEXT NOT NULL,
      details TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Seed Default Users if empty
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  if (userCount === 0) {
    console.log('[+] Seeding initial SOC users into SQLite database...');
    const salt = bcrypt.genSaltSync(10);
    const insertUser = db.prepare(`
      INSERT INTO users (username, password_hash, role, full_name)
      VALUES (?, ?, ?, ?)
    `);

    insertUser.run('admin', bcrypt.hashSync('admin123', salt), 'admin', 'SOC Operations Director');
    insertUser.run('analyst', bcrypt.hashSync('analyst123', salt), 'analyst', 'Senior Tier-2 Analyst');
    insertUser.run('auditor', bcrypt.hashSync('auditor123', salt), 'viewer', 'Compliance Auditor');
    console.log('[+] Seeded default accounts: admin (admin123), analyst (analyst123), auditor (auditor123)');
  }
}

// User Helpers
function findUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function createUser(username, password, role = 'analyst', full_name = '') {
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);
  const stmt = db.prepare(`
    INSERT INTO users (username, password_hash, role, full_name)
    VALUES (?, ?, ?, ?)
  `);
  stmt.run(username, hash, role, full_name || username);
  return findUserByUsername(username);
}

// Alerts Helpers
function insertAlert(alert) {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO alerts (id, timestamp, source_ip, location, prediction, confidence, report)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    alert.id || Date.now(),
    alert.timestamp || new Date().toISOString(),
    alert.source_ip || '0.0.0.0',
    alert.location || 'Unknown',
    alert.prediction || 'Normal',
    alert.confidence || 0,
    alert.report || ''
  );
}

function getRecentAlerts(limit = 60) {
  return db.prepare(`
    SELECT * FROM alerts 
    ORDER BY id DESC 
    LIMIT ?
  `).all(limit);
}

function getFilteredHistory({ search = '', type = '', limit = 50, offset = 0 }) {
  let query = 'SELECT * FROM alerts WHERE 1=1';
  const params = [];

  if (type && type !== 'ALL') {
    query += ' AND prediction = ?';
    params.push(type);
  }

  if (search) {
    query += ' AND (source_ip LIKE ? OR location LIKE ? OR report LIKE ?)';
    const s = `%${search}%`;
    params.push(s, s, s);
  }

  // Count total
  const countQuery = query.replace('SELECT *', 'SELECT COUNT(*) as count');
  const total = db.prepare(countQuery).get(...params).count;

  query += ' ORDER BY id DESC LIMIT ? OFFSET ?';
  params.push(Number(limit), Number(offset));

  const results = db.prepare(query).all(...params);
  return { total, results, limit, offset };
}

function clearAllAlerts() {
  db.exec('DELETE FROM alerts');
}

// Firewall Helpers
function blockIP(ip, reason = 'Automated Active Defense', blocked_by = 'AI Gateway') {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_by, blocked_at, active)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP, 1)
  `);
  stmt.run(ip, reason, blocked_by);
}

function unblockIP(ip) {
  const stmt = db.prepare('UPDATE blocked_ips SET active = 0 WHERE ip = ?');
  stmt.run(ip);
}

function getActiveBlockedIPs() {
  const rows = db.prepare('SELECT ip FROM blocked_ips WHERE active = 1').all();
  return rows.map(r => r.ip);
}

function clearBlockedIPs() {
  db.exec('UPDATE blocked_ips SET active = 0');
}

// Audit Log Helpers
function addAuditLog(username, action, details = '') {
  const stmt = db.prepare(`
    INSERT INTO audit_logs (username, action, details)
    VALUES (?, ?, ?)
  `);
  stmt.run(username, action, details);
}

function getAuditLogs(limit = 30) {
  return db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?').all(limit);
}

// Overall Stats Helper
function getDatabaseStats() {
  const total = db.prepare('SELECT COUNT(*) as c FROM alerts').get().c;
  const normal = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE prediction = 'Normal'").get().c;
  const attack = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE prediction = 'Attack'").get().c;
  const blocked = db.prepare("SELECT COUNT(*) as c FROM alerts WHERE prediction = 'Blocked'").get().c;
  const blockedCount = db.prepare("SELECT COUNT(*) as c FROM blocked_ips WHERE active = 1").get().c;
  const attackRate = total > 0 ? (attack / total) : 0;

  return { total, normal, attack, blocked, blockedCount, attackRate };
}

// Initialize on require
initDatabase();

module.exports = {
  db,
  findUserByUsername,
  createUser,
  insertAlert,
  getRecentAlerts,
  getFilteredHistory,
  clearAllAlerts,
  blockIP,
  unblockIP,
  getActiveBlockedIPs,
  clearBlockedIPs,
  addAuditLog,
  getAuditLogs,
  getDatabaseStats
};
