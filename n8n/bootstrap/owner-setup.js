// Creates the n8n owner account once (idempotent) so the UI is usable after `make up`.
const e = process.env;
const body = JSON.stringify({ email: e.N8N_OWNER_EMAIL, firstName: "ScamSaathi", lastName: "Admin", password: e.N8N_OWNER_PASSWORD });
async function main() {
  for (let i = 0; i < 90; i++) {
    try {
      const h = await fetch("http://127.0.0.1:5678/healthz");
      if (h.ok) {
        const r = await fetch("http://127.0.0.1:5678/rest/owner/setup", { method: "POST", headers: { "Content-Type": "application/json" }, body });
        if (r.status !== 404) {  // 404 = REST routes not registered yet
          console.log(`[bootstrap] owner setup: HTTP ${r.status}${r.status === 400 ? " (already set up)" : ""}`);
          return;
        }
      }
    } catch (_) {}
    await new Promise((res) => setTimeout(res, 2000));
  }
}
main();
