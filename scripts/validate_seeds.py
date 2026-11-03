"""CI gate (SRS 6.6): every registry policy needs `quote` + `source_url`; counts must match Phase 3."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "analyzer"))
from app.registry import SeedError, load_seed_dir  # noqa: E402

try:
    entities, playbooks = load_seed_dir(ROOT / "registry" / "seed")
except SeedError as exc:
    print(f"seed validation FAILED: {exc}")
    sys.exit(1)
banks = sum(e["kind"] == "bank" for e in entities)
insurers = sum(e["kind"] == "insurer" for e in entities)
print(f"seeds OK: {banks} banks, {insurers} insurers, {len(playbooks)} playbooks, "
      f"{sum(len(e['policies']) for e in entities)} policies (all with quote + source_url)")
sys.exit(0 if (banks, insurers, len(playbooks)) == (15, 10, 15) else 1)
