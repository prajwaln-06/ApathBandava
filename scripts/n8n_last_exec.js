// Debug helper: summarise recent n8n executions (per-node timing, errors, key outputs).
// Usage: docker compose exec -T n8n node /bootstrap/../scripts-n8n/n8n_last_exec.js [workflowName] [count]
// (scripts/tasks.sh `n8n-exec` copies this file into the container and runs it.)
const path = require("path");
const base = "/usr/local/lib/node_modules/n8n/node_modules";
const sqlite3 = require(path.join(base, "sqlite3"));
const { parse } = require(path.join(base, "flatted"));
const wfName = process.argv[2] || "10-check";
const count = Number(process.argv[3] || 1);
const db = new sqlite3.Database("/home/node/.n8n/database.sqlite", sqlite3.OPEN_READONLY);
db.all(
  `SELECT e.id, e.status, e.startedAt, e.stoppedAt, d.data FROM execution_entity e
   JOIN execution_data d ON d.executionId = e.id JOIN workflow_entity w ON w.id = e.workflowId
   WHERE w.name = ? ORDER BY e.id DESC LIMIT ?`, [wfName, count],
  (err, rows) => {
    if (err) { console.error(err); process.exit(1); }
    for (const r of rows) {
      const data = parse(r.data);
      const run = data.resultData.runData || {};
      console.log(`# exec ${r.id} ${r.status} ${r.startedAt} -> ${r.stoppedAt}`);
      if (data.resultData.error) console.log("  WORKFLOW ERROR:", data.resultData.error.message);
      for (const [node, runs] of Object.entries(run)) {
        for (const x of runs) {
          const out = x.data && x.data.main && x.data.main[0] ? x.data.main[0].map(i => i.json) : [];
          const err = x.error ? ` ERROR: ${x.error.message} ${x.error.description || ""}` : "";
          console.log(`  ${String(x.executionTime).padStart(6)} ms  ${node}${err}`);
          if (process.env.SHOW && process.env.SHOW.split(",").some(s => node.includes(s))) {
            console.log("    ", JSON.stringify(out).slice(0, Number(process.env.LEN || 1500)));
          }
        }
      }
    }
  });
