"""Every API route used by the demo scripts must exist in docs/api/openapi.yaml (method + path)."""
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
spec = (root / "docs/api/openapi.yaml").read_text()
norm = lambda p: re.sub(r"\{[^}]*\}", "{}", p)
paths, cur = {}, None
for line in spec.splitlines():
    m = re.match(r"^  (/\S*):\s*$", line)
    if m:
        cur = norm(m.group(1)); paths[cur] = set(); continue
    m = re.match(r"^    (get|post|put|patch|delete):\s*$", line)
    if m and cur:
        paths[cur].add(m.group(1).upper())
    if re.match(r"^\S", line):
        cur = None
used = set()
call = re.compile(r'api_(get|post|put|patch|delete) +"?(/[^"?\s|)]*)')
for f in [root / "demo/lib.sh", *sorted((root / "demo/scenarios").glob("*.sh")), root / "demo/up.sh"]:
    for m in call.finditer(f.read_text()):
        p = re.sub(r"\$\([^)]*\)\)?|\$\{?[A-Za-z_0-9][A-Za-z0-9_]*\}?", "{}", m.group(2))
        if p == "/{}":  # load_policy: POST /<collection> for every collection of the document
            for c in ["zones", "objects", "services", "data-classes", "agents", "rules", "inspection-rules"]:
                used.add(("POST", "/" + c, f.name))
            continue
        used.add((m.group(1).upper(), p, f.name))
bad = [(m, p, f) for m, p, f in sorted(used) if m not in paths.get(p, set())]
for m, p, f in sorted(used):
    print(("MISSING " if (m, p, f) in bad else "ok      ") + f"{m:6} {p}  ({f})")
sys.exit(1 if bad or not used else 0)
