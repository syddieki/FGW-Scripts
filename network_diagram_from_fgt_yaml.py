# network_diagram_from_fgt_yaml.py

import yaml
from pathlib import Path
from ipaddress import ip_network

# ---- 1. Load YAML ----

def load_fgt_yaml(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)

# ---- 2. Helpers to normalise data ----

def normalise_zone_map(config):
    """
    Returns:
      interface_to_zone: {"port2": "LAN_ZONE", ...}
      zone_to_interfaces: {"LAN_ZONE": ["port2", ...], ...}
    """
    interface_to_zone = {}
    zone_to_interfaces = {}

    zones = config.get("config_system_zone", []) or []
    for z in zones:
        zname = z.get("name")
        ifaces = z.get("interface", []) or []
        zone_to_interfaces.setdefault(zname, [])
        for iface in ifaces:
            interface_to_zone[iface] = zname
            zone_to_interfaces[zname].append(iface)

    return interface_to_zone, zone_to_interfaces

def normalise_interfaces(config):
    """
    Returns: {"port2": {"ip": "10.0.10.1/24", "role": "lan", ...}, ...}
    """
    interfaces = {}
    for iface in config.get("config_system_interface", []) or []:
        name = iface.get("name")
        if not name:
            continue
        interfaces[name] = iface
    return interfaces

def normalise_addresses(config):
    """
    Map address object name -> CIDR or text (best effort)
    """
    addr_map = {}
    for addr in config.get("config_firewall_address", []) or []:
        name = addr.get("name")
        if not name:
            continue
        if "subnet" in addr:
            # e.g. "10.0.10.0 255.255.255.0"
            subnet, mask = addr["subnet"].split()
            network = ip_network(f"{subnet}/{mask}", strict=False)
            addr_map[name] = str(network)
        elif addr.get("type") == "iprange":
            start_ip = addr.get("start_ip")
            end_ip = addr.get("end_ip")
            addr_map[name] = f"{start_ip}-{end_ip}"
        else:
            # fallback
            addr_map[name] = addr.get("subnet") or "unknown"
    return addr_map

# ---- 3. Build logical flows (edges) ----

def extract_flows(config, interface_to_zone, addr_map):
    """
    Each flow is a dict with:
      src_zone, dst_zone, src_addrs, dst_addrs, services, action, policyid
    """
    flows = []
    for pol in config.get("config_firewall_policy", []) or []:
        action = pol.get("action", "accept")
        if action != "accept":
            continue  # for diagram clarity, ignore denies by default

        srcintfs = pol.get("srcintf", []) or []
        dstintfs = pol.get("dstintf", []) or []
        srcaddr_names = pol.get("srcaddr", []) or []
        dstaddr_names = pol.get("dstaddr", []) or []
        services = pol.get("service", []) or []
        pid = pol.get("policyid")

        # Map interfaces/zones to zones (FortiGate often uses interface or zone names here)
        src_zones = [interface_to_zone.get(i, i) for i in srcintfs]
        dst_zones = [interface_to_zone.get(i, i) for i in dstintfs]

        # Map address objects to CIDRs/text
        src_addrs = [addr_map.get(a, a) for a in srcaddr_names]
        dst_addrs = [addr_map.get(a, a) for a in dstaddr_names]

        for sz in src_zones:
            for dz in dst_zones:
                flows.append({
                    "src_zone": sz,
                    "dst_zone": dz,
                    "src_addrs": src_addrs,
                    "dst_addrs": dst_addrs,
                    "services": services,
                    "action": action,
                    "policyid": pid,
                })
    return flows

# ---- 4. Generate Mermaid diagram text ----

def generate_mermaid(flows, zone_to_interfaces, interfaces):
    """
    Generate a high-level zone-to-zone diagram.
    You can refine this to show interfaces and subnets as separate nodes.
    """
    lines = []
    lines.append("flowchart LR")

    # Declare zones as subgraphs and show their interfaces
    for zone, ifaces in zone_to_interfaces.items():
        lines.append(f"  subgraph {zone}")
        for iface in ifaces:
            iface_obj = interfaces.get(iface, {})
            ip_cidr = iface_obj.get("ip", "")
            label = f"{iface}\\n{ip_cidr}" if ip_cidr else iface
            lines.append(f"    {iface}([{label}])")
        lines.append("  end")

    # Add edges between zones based on flows
    # To avoid duplication, use a set of (src_zone, dst_zone, label) keys
    seen_edges = set()
    for f in flows:
        src_zone = f["src_zone"]
        dst_zone = f["dst_zone"]
        services_str = ", ".join(f["services"]) if f["services"] else "ANY"
        src_subnets = ", ".join(f["src_addrs"])
        dst_subnets = ", ".join(f["dst_addrs"])

        label = f"Policy {f['policyid']}\\n{services_str}\\n{src_subnets} → {dst_subnets}"
        key = (src_zone, dst_zone, label)
        if key in seen_edges:
            continue
        seen_edges.add(key)

        # Use the zone names as nodes
        lines.append(f"  {src_zone} -->|\"{label}\"| {dst_zone}")

    return "\n".join(lines)

# ---- 5. Main wrapper ----

def main():
    cfg = load_fgt_yaml("fortigate_backup.yaml")
    interfaces = normalise_interfaces(cfg)
    interface_to_zone, zone_to_interfaces = normalise_zone_map(cfg)
    addr_map = normalise_addresses(cfg)
    flows = extract_flows(cfg, interface_to_zone, addr_map)
    mermaid = generate_mermaid(flows, zone_to_interfaces, interfaces)

    out_path = Path("fortigate_network_diagram.mmd")
    out_path.write_text(mermaid, encoding="utf-8")
    print(f"Mermaid diagram written to {out_path}")

if __name__ == "__main__":
    main()
