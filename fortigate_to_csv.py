# file: fortigate_to_csv.py
import json
import csv
from collections import defaultdict

CONFIG_FILE = "fortigate_config.json"
OUTPUT_CSV = "fortigate_edges.csv"

with open(CONFIG_FILE) as f:
    cfg = json.load(f)

policies = cfg.get("firewall.policy", [])

def is_enabled(p):
    return p.get("status", "enable") == "enable"

def is_accept(p):
    return p.get("action", "accept") == "accept"

def norm_list(x):
    if isinstance(x, dict):
        return [x.get("name", "UNKNOWN")]
    if isinstance(x, list):
        out = []
        for i in x:
            if isinstance(i, dict):
                out.append(i.get("name", "UNKNOWN"))
            else:
                out.append(str(i))
        return out
    if isinstance(x, str):
        return [x]
    return []

edges = defaultdict(lambda: {"count": 0, "services": set()})

for p in policies:
    if not (is_enabled(p) and is_accept(p)):
        continue

    srcintf = norm_list(p.get("srcintf", []))
    dstintf = norm_list(p.get("dstintf", []))
    services = norm_list(p.get("service", []))

    for si in srcintf:
        for di in dstintf:
            key = (si, di)
            edges[key]["count"] += 1
            for s in services:
                edges[key]["services"].add(s)

with open(OUTPUT_CSV, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["source", "target", "label", "rule_count"])
    for (si, di), info in edges.items():
        svc_preview = ", ".join(sorted(info["services"]))[:60]
        label = f"{info['count']} rules"
        if svc_preview:
            label += f" - {svc_preview}"
        writer.writerow([si, di, label, info["count"]])

print(f"Wrote {OUTPUT_CSV}")
