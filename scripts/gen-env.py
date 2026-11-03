"""Create .env from .env.example, filling every <secret> with a random value. Never overwrites."""
import secrets
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
env, example = root / ".env", root / ".env.example"
if env.exists():
    print(".env already exists; leaving it unchanged")
    sys.exit(0)
out = []
for line in example.read_text(encoding="utf-8").splitlines():
    if line.endswith("=<secret>"):
        key = line.split("=", 1)[0]
        val = secrets.token_hex(16) if key == "N8N_OWNER_PASSWORD" else secrets.token_urlsafe(32)
        if key == "N8N_OWNER_PASSWORD":
            val = "Ss1" + val  # n8n requires upper, lower and a digit
        line = f"{key}={val}"
    out.append(line)
env.write_text("\n".join(out) + "\n", encoding="utf-8")
print("wrote .env with fresh secrets; now edit the LLM / WhatsApp sections")
