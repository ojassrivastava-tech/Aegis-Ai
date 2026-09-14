const assert = require("assert");
const db = require("../server/db");
const copilot = require("../server/copilot");

async function runTests() {
  console.log("Starting AEGIS Node Backend & Copilot Test Suite...");

  // 1. Test Database Operations
  console.log("1. Testing SQLite DB Layer...");
  const initialStats = db.getDatabaseStats();
  assert(typeof initialStats.total === "number", "Total packets must be a number");
  assert(typeof initialStats.attack === "number", "Attack packets must be a number");

  const testAlert = {
    id: 99999901,
    timestamp: new Date().toISOString(),
    prediction: "Attack",
    confidence: 0.98,
    source_ip: "198.51.100.99",
    location: "Frankfurt, Germany",
    report: "TEST ALERT REPORT"
  };

  db.insertAlert(testAlert);
  const recent = db.getRecentAlerts(5);
  const foundAlert = recent.find(a => a.id === testAlert.id);
  assert(foundAlert, "Inserted alert must be retrievable from SQLite");
  assert.strictEqual(foundAlert.source_ip, "198.51.100.99");
  console.log("   ✓ SQLite alert insert & fetch passed");

  // 2. Test Blocklist DB
  db.blockIP("198.51.100.99", "Automated Test Rule", "TestAgent");
  const blockedList = db.getActiveBlockedIPs();
  assert(blockedList.includes("198.51.100.99"), "Blocked IP must exist in active blocked IPs");
  db.unblockIP("198.51.100.99");
  const afterRemove = db.getActiveBlockedIPs();
  assert(!afterRemove.includes("198.51.100.99"), "Blocked IP must be removed from active blocked IPs");
  console.log("   ✓ SQLite blocklist block & unblock passed");

  // 3. Test Copilot Core Responses & Actions
  console.log("2. Testing Copilot Reasoner & Security Intent Mapping...");
  let mockLockdown = false;
  const mockBlockedSet = new Set();
  const mockIo = { emit: () => {} };

  // Status Query
  const statusRes = await copilot.processCopilotMessage({
    message: "status",
    user: { username: "TestOperator" },
    db,
    blockedIPs: mockBlockedSet,
    getStats: () => db.getDatabaseStats(),
    io: mockIo,
    isLockdownRef: () => mockLockdown,
    setLockdown: (val) => { mockLockdown = val; }
  });
  assert(statusRes && statusRes.reply, "Copilot must return a reply for 'status'");
  assert(statusRes.reply.includes("SITUATION REPORT") || statusRes.reply.includes("AEGIS"), "Reply must format SOC situational status");
  console.log("   ✓ Copilot status briefing passed");

  // Action: Block IP
  const blockRes = await copilot.processCopilotMessage({
    message: "block 192.0.2.77",
    user: { username: "TestOperator" },
    db,
    blockedIPs: mockBlockedSet,
    getStats: () => db.getDatabaseStats(),
    io: mockIo,
    isLockdownRef: () => mockLockdown,
    setLockdown: (val) => { mockLockdown = val; }
  });
  assert(blockRes.actionExecuted && blockRes.actionExecuted.type === "BLOCK", "Copilot must execute BLOCK action");
  assert.strictEqual(blockRes.actionExecuted.ip, "192.0.2.77");
  assert(mockBlockedSet.has("192.0.2.77"), "In-memory blocked set must contain blocked IP");
  console.log("   ✓ Copilot autonomous IP block action passed");

  // Action: Unblock IP
  const unblockRes = await copilot.processCopilotMessage({
    message: "unblock 192.0.2.77",
    user: { username: "TestOperator" },
    db,
    blockedIPs: mockBlockedSet,
    getStats: () => db.getDatabaseStats(),
    io: mockIo,
    isLockdownRef: () => mockLockdown,
    setLockdown: (val) => { mockLockdown = val; }
  });
  assert(unblockRes.actionExecuted && unblockRes.actionExecuted.type === "UNBLOCK", "Copilot must execute UNBLOCK action");
  assert(!mockBlockedSet.has("192.0.2.77"), "In-memory blocked set must have IP removed");
  console.log("   ✓ Copilot autonomous IP unblock action passed");

  // Action: DEFCON-1 Lockdown
  const lockdownRes = await copilot.processCopilotMessage({
    message: "lockdown enable",
    user: { username: "TestOperator" },
    db,
    blockedIPs: mockBlockedSet,
    getStats: () => db.getDatabaseStats(),
    io: mockIo,
    isLockdownRef: () => mockLockdown,
    setLockdown: (val) => { mockLockdown = val; }
  });
  assert(lockdownRes.actionExecuted && lockdownRes.actionExecuted.type === "LOCKDOWN_ON", "Copilot must engage lockdown");
  assert.strictEqual(mockLockdown, true, "Lockdown flag must be active");
  console.log("   ✓ Copilot DEFCON-1 Lockdown action passed");

  // Cyber Knowledge Base Query: DoS
  const dosRes = await copilot.processCopilotMessage({
    message: "What is a DoS attack and how do we mitigate it?",
    user: { username: "TestOperator" },
    db,
    blockedIPs: mockBlockedSet,
    getStats: () => db.getDatabaseStats(),
    io: mockIo,
    isLockdownRef: () => mockLockdown,
    setLockdown: (val) => { mockLockdown = val; }
  });
  assert(dosRes.reply.includes("Denial of Service") || dosRes.reply.includes("DoS"), "Copilot must return DoS defense explanation");
  console.log("   ✓ Copilot Cybersecurity Knowledge Base retrieval passed");

  console.log("\nALL NODE BACKEND & COPILOT TESTS PASSED SUCCESSFULLY! ✓\n");
}

runTests().catch(err => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
