# file: fortigate_to_csv_zones.py
import json
import csv
from collections import defaultdict

CONFIG_FILE = "fortigate_config.json"
OUTPUT_CSV = "fortigate_edges_zones.csv"

with open(CONFIG_FILE) as f:
    cfg = json.load(f)

# 1) Build interface → zone mapping from firewall.zone
zone_entries = cfg.get("firewall.zone", [])
intf_to_zone = {}

def norm_list_any(x):
    if isinstance(x, dict):
        return [x]
    if isinstance(x, list):
        return x
    return [x]

for z in zone_entries:
    zname = z.get("name")
    if not zname:
        continue
    members = norm_list_any(z.get("interface", []))
    for mem in members:
        if isinstance(mem, dict):
            iname = mem.get("name")
        else:
            iname = str(mem)
        if iname:
            intf_to_zone[iname] = zname

def map_to_zone_or_intf(name: str) -> str:
    """
    If interface is in a zone, return zone name.
    Otherwise return the interface name itself.
    """
    return intf_to_zone.get(name, name)

# 2) Process firewall policies → zone-level edges
policies = cfg.get("firewall.policy", [])

def is_enabled(p):
    return p.get("status", "enable") == "enable"

def is_accept(p):
    return p.get("action", "accept") == "accept"

def norm_to_name_list(x):
    """
    Normalize FortiGate-style lists that may be:
      - list of dicts with 'name'
      - list of strings
      - single dict with 'name'
      - single string
    """
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

    srcintf_list = norm_to_name_list(p.get("srcintf", []))
    dstintf_list = norm_to_name_list(p.get("dstintf", []))
    service_list = norm_to_name_list(p.get("service", []))

    for si_raw in srcintf_list:
        for di_raw in dstintf_list:
            # Map interfaces to zones where possible
            src_zone = map_to_zone_or_intf(si_raw)
            dst_zone = map_to_zone_or_intf(di_raw)

            key = (src_zone, dst_zone)
            edges[key]["count"] += 1
            for s in service_list:
                edges[key]["services"].add(s)

# 3) Write zone-level edges to CSV for draw.io
with open(OUTPUT_CSV, "w", newline="") as f:
    writer = csv.writer(f)
    # You can add more columns if you want to use them in draw.io
    writer.writerow(["source", "target", "label", "rule_count"])

    for (src_zone, dst_zone), info in edges.items():
        # Optional: skip very small relationships to declutter
        # if info["count"] < 2:
        #     continue

        services_sorted = sorted(info["services"])
        svc_preview = ", ".join(services_sorted)[:80]
        label = f"{info['count']} rule(s)"
        if svc_preview:
            label += f" - {svc_preview}"

        writer.writerow([src_zone, dst_zone, label, info["count"]])

print(f"Wrote {OUTPUT_CSV}")
