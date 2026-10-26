"""Network enumeration: interfaces, addresses, DNS, routes, rules, neighbours, sockets with UID attribution, accounting."""
from __future__ import annotations

from collections import Counter, defaultdict

from . import parsers as P
from .adb import OK
from .model import Ctx, Spec, table, fence, details, or_na, fmt_bytes

TUNNEL_PREFIXES = ("tun", "ppp", "wg", "tap", "ipsec", "xfrm", "vti", "gre", "sit", "ip6tnl", "rmnet_ipa")


def _owner_resolver(ctx: Ctx):
    cache: dict[int, str] = {}
    fixed = {v: k for k, v in P.FIXED_UIDS.items()}

    def who(uid: int) -> str:
        if uid in cache:
            return cache[uid]
        base = uid % 100000
        pk = ctx.uid_map.get(base) or ctx.uid_map.get(uid)
        if pk:
            res = ", ".join(sorted(pk)[:2]) + (" ..." if len(pk) > 2 else "")
        elif base in fixed:
            res = fixed[base]
        else:
            res = f"uid {uid}"
        cache[uid] = res
        return res
    return who


def collect_network(ctx: Ctx) -> None:
    adb = ctx.adb
    st = ctx.setting
    specs = [
        Spec("ip_addr", "ip addr", ["ip addr", "ip -4 addr"], 0, parser=P.parse_ip_addr, show=0),
        Spec("if_inet6", "/proc/net/if_inet6", ["cat /proc/net/if_inet6"], 0, parser=P.parse_if_inet6, show=0),
        Spec("ifconfig", "ifconfig -a (fallback)", ["ifconfig -a"], 1, show=0, needs=("ifconfig",)),
        Spec("ip_link_stats", "ip -s link", ["ip -s link"], 1, show=0),
        Spec("net_dev", "/proc/net/dev", ["cat /proc/net/dev"], 0, parser=P.parse_proc_net_dev, show=0),
        Spec("route4", "IPv4 routes (all tables)", ["ip -4 route show table all", "ip route show table all", "ip route", "cat /proc/net/route"], 0, parser=P.parse_ip_route, show=0),
        Spec("route6", "IPv6 routes (all tables)", ["ip -6 route show table all", "ip -6 route", "cat /proc/net/ipv6_route"], 0, parser=P.parse_ip_route, show=0),
        Spec("rule4", "IPv4 policy rules", ["ip rule"], 0, parser=P.parse_ip_rule, show=0),
        Spec("rule6", "IPv6 policy rules", ["ip -6 rule"], 1, parser=P.parse_ip_rule, show=0),
        Spec("neigh", "Neighbour table", ["ip neigh show", "ip neigh"], 0, parser=P.parse_ip_neigh, show=0),
        Spec("arp", "/proc/net/arp", ["cat /proc/net/arp"], 0, parser=P.parse_proc_net_arp, show=0),
        Spec("xfrm_state", "IPsec SAs (ip xfrm state)", ["ip xfrm state"], 2, show=20),
        Spec("xfrm_policy", "IPsec policies (ip xfrm policy)", ["ip xfrm policy"], 2, show=20),
        Spec("ss", "ss -tunap (extended sockets)", ["ss -tunape", "ss -tunap", "ss -tuna"], 1, show=0, needs=("ss",)),
        Spec("netstat", "netstat -tunap (fallback)", ["netstat -tunap", "netstat -tuna"], 2, show=0, needs=("netstat",)),
        Spec("conntrack", "/proc/net/nf_conntrack", ["cat /proc/net/nf_conntrack"], 2, show=0),
        Spec("sockstat", "/proc/net/sockstat", ["cat /proc/net/sockstat"], 1, show=10),
        Spec("iptables", "iptables -S", ["iptables -S"], 2, show=0, needs=("iptables",)),
        Spec("xt_qtaguid", "Per-UID counters (xt_qtaguid)", ["cat /proc/net/xt_qtaguid/stats"], 1, show=0),
        Spec("dns_props", "DNS properties", ['for i in 1 2 3 4; do echo "net.dns$i=$(getprop net.dns$i)"; done; echo "http.proxy=$(getprop http.proxy)"'], 0, parser=P.parse_kv_lines, show=6),
        Spec("connectivity", "dumpsys connectivity", ["dumpsys connectivity"], 0, timeout=60, show=0),
        Spec("dnsresolver", "dumpsys dnsresolver", ["dumpsys dnsresolver"], 1, timeout=60, show=0),
        Spec("netstats_detail", "dumpsys netstats (per-UID history)", ["dumpsys netstats detail", "dumpsys netstats --full", "dumpsys netstats"], 1, timeout=90, show=0),
        Spec("netpolicy", "dumpsys netpolicy", ["dumpsys netpolicy"], 1, timeout=60, show=0),
        Spec("wifi", "dumpsys wifi", ["dumpsys wifi"], 0, timeout=60, parser=P.parse_wifi, show=0),
        Spec("wifi_status", "cmd wifi status", ["cmd wifi status"], 0, show=30),
        Spec("wifi_saved", "Saved Wi-Fi networks (metadata via cmd wifi)", ["cmd wifi list-networks"], 0, show=40),
        Spec("wifi_scan", "Wi-Fi scan results", ["cmd wifi list-scan-results"], 2, show=30),
        Spec("bluetooth", "dumpsys bluetooth_manager", ["dumpsys bluetooth_manager"], 0, timeout=60, parser=P.parse_bonded_bt, show=0),
        Spec("telephony", "dumpsys telephony.registry", ["dumpsys telephony.registry"], 1, timeout=60, show=0),
        Spec("vpn", "dumpsys vpn_management", ["dumpsys vpn_management"], 1, timeout=60, show=0),
    ]
    items = {i.key: i for i in ctx.run_specs(specs)}
    ifaces = items["ip_addr"].parsed or []
    v6 = items["if_inet6"].parsed or []
    if not ifaces and (v6 or items["net_dev"].parsed):
        names = {d["iface"] for d in (items["net_dev"].parsed or [])}
        ifaces = [{"name": n, "flags": [], "state": None, "mac": None, "mtu": 0,
                   "addresses": [{"family": "inet6", "address": a["address"], "scope": None} for a in v6 if a["iface"] == n]} for n in sorted(names)]
    tunnels = sorted({i["name"] for i in ifaces if i["name"].startswith(TUNNEL_PREFIXES)} | {d["iface"] for d in (items["net_dev"].parsed or []) if d["iface"].startswith(TUNNEL_PREFIXES)})
    conn_txt = items["connectivity"].text
    dns = P.parse_dns(conn_txt)
    dns_props = {k: v for k, v in (items["dns_props"].parsed or {}).items() if v}
    proxy = {k: ctx.setting("global", k) for k in ("http_proxy", "global_http_proxy_host", "global_http_proxy_port", "global_http_proxy_exclusion_list", "global_proxy_pac_url")}
    private_dns = (ctx.setting("global", "private_dns_mode"), ctx.setting("global", "private_dns_specifier"))
    summary_rows = [["Airplane mode", st("global", "airplane_mode_on")], ["Wi-Fi on", st("global", "wifi_on")], ["Bluetooth on", st("global", "bluetooth_on")],
                    ["Mobile data / roaming", f"{st('global', 'mobile_data')} / {st('global', 'data_roaming')}"],
                    ["Private DNS mode / host", " / ".join(private_dns)], ["DNS servers (connectivity dump / props)", f"{', '.join(dns) or 'n/a'} / {', '.join(dns_props.values()) or 'n/a'}"],
                    ["Proxy settings", ", ".join(f"{k}={v}" for k, v in proxy.items() if v != "n/a") or "none set"],
                    ["VPN/tunnel interfaces", ", ".join(tunnels) or "none"],
                    ["Always-on VPN", st("secure", "always_on_vpn_app")]]
    body = table(["Item", "Value"], summary_rows)
    body += "\n\n**Interfaces and addresses (IPv4 and IPv6)**\n\n" + table(["Iface", "State", "MAC", "MTU", "Addresses"], [
        [i["name"], i.get("state") or "", i.get("mac") or "", i.get("mtu") or "", ", ".join(f"{a['address']}" for a in i["addresses"])] for i in ifaces])
    dev = items["net_dev"].parsed or []
    if dev:
        body += "\n\n**Interface statistics** (`/proc/net/dev`)\n\n" + table(["Iface", "RX", "TX", "RX pkts", "TX pkts", "RX err", "TX err"], [
            [d["iface"], fmt_bytes(d["rx_bytes"]), fmt_bytes(d["tx_bytes"]), d["rx_packets"], d["tx_packets"], d["rx_errs"], d["tx_errs"]] for d in dev])
    for key, title in (("route4", "IPv4 routes"), ("route6", "IPv6 routes")):
        if items[key].parsed:
            body += f"\n\n**{title}** ({len(items[key].parsed)})\n\n" + table(["Destination", "Via", "Dev", "Table", "Proto", "Src"], [
                [r.get("dst"), r.get("via", ""), r.get("dev", ""), r.get("table", "main"), r.get("proto", ""), r.get("src", "")] for r in items[key].parsed[:200]])
    rules = (items["rule4"].parsed or []) + (items["rule6"].parsed or [])
    if rules:
        body += "\n\n" + details(f"Policy rules ({len(rules)})", table(["Priority", "Rule"], [[r["priority"], r["rule"]] for r in rules]))
    neigh = items["neigh"].parsed or items["arp"].parsed or []
    if neigh:
        body += "\n\n**Neighbours / ARP**\n\n" + table(["IP", "Dev", "MAC", "State"], [[n["ip"], n["dev"], n.get("mac") or "", n.get("state", "")] for n in neigh])
    wifi = items["wifi"].parsed or {}
    body += "\n\n**Wireless state**\n\n" + table(["Item", "Value"], [["Wi-Fi enabled (dumpsys wifi)", or_na(wifi.get("wifi_enabled"))], ["Current connection info", or_na(wifi.get("wifi_info"))],
                                                                   ["Configured networks seen in dump", wifi.get("configured_networks", "n/a")]])
    bt = items["bluetooth"].parsed or []
    if bt:
        body += "\n\n**Bonded Bluetooth devices**\n\n" + table(["Address", "Type", "Name"], [[b["address"], b["type"], b["name"]] for b in bt])

    # ---- sockets with UID attribution
    socks: list[dict] = []
    for fname in ("tcp", "tcp6", "udp", "udp6", "raw", "raw6"):
        r = adb.shell(f"cat /proc/net/{fname}", label=f"proc-net-{fname}")
        if r.ok:
            socks += P.parse_proc_net(r.stdout, fname)
    unix = P.parse_proc_net_unix(adb.text("cat /proc/net/unix", label="proc-net-unix")) if ctx.level >= 1 else []
    ctx.sockets = socks
    who = _owner_resolver(ctx)
    for s in socks:
        s["owner"] = who(s["uid"])
    lo = ("127.", "::1")
    listening = [s for s in socks if s["state"] == "LISTEN"]
    established = [s for s in socks if s["state"] == "ESTABLISHED" and not s["remote"].startswith(lo)]
    udp_bound = [s for s in socks if s["proto"].startswith("udp") and s["state"] == "UNCONN" and not s["local"].startswith(lo) and not s["local"].endswith(":0")]
    if socks:
        body += "\n\n### Listening TCP sockets\n\n" + table(["Proto", "Local", "UID", "Owner"], [[s["proto"], s["local"], s["uid"], s["owner"]] for s in listening[:300]])
        agg: dict = defaultdict(lambda: {"n": 0, "ips": Counter()})
        for s in established:
            agg[s["owner"]]["n"] += 1
            agg[s["owner"]]["ips"][s["remote"].rsplit(":", 1)[0]] += 1
        body += "\n\n### Established TCP connections by owner\n\n" + table(["Owner", "Connections", "Unique remote IPs", "Most-used remote"], [
            [o, v["n"], len(v["ips"]), v["ips"].most_common(1)[0][0]] for o, v in sorted(agg.items(), key=lambda kv: -kv[1]["n"])])
        body += "\n\n" + details(f"Established TCP connections ({len(established)})", table(["Proto", "Local", "Remote", "UID", "Owner"], [[s["proto"], s["local"], s["remote"], s["uid"], s["owner"]] for s in established[:500]]))
        body += "\n\n" + details(f"Bound UDP sockets, non-loopback ({len(udp_bound)})", table(["Proto", "Local", "UID", "Owner"], [[s["proto"], s["local"], s["uid"], s["owner"]] for s in udp_bound[:300]]))
    else:
        body += "\n\n_`/proc/net/*` socket tables were not readable from the adb shell; socket-to-UID attribution is therefore unavailable (see command inventory)._"
    if unix:
        body += "\n\n" + details(f"UNIX sockets ({len(unix)})", table(["Type", "State", "Path"], [[u["type"], u["state"], u["path"]] for u in unix[:300]]))

    # ---- per-UID accounting
    uid_acct = P.parse_netstats_uid(items["netstats_detail"].text)
    if not uid_acct and items["xt_qtaguid"].text:
        for ln in items["xt_qtaguid"].text.splitlines()[1:]:
            f = ln.split()
            if len(f) >= 9 and f[3].isdigit():
                a = uid_acct.setdefault(int(f[3]), {"rx_bytes": 0, "tx_bytes": 0})
                a["rx_bytes"] += int(f[5]) if f[5].isdigit() else 0
                a["tx_bytes"] += int(f[7]) if f[7].isdigit() else 0
    if uid_acct:
        top = sorted(uid_acct.items(), key=lambda kv: -(kv[1]["rx_bytes"] + kv[1]["tx_bytes"]))[:30]
        body += "\n\n**Per-UID network accounting (available history)**\n\n" + table(["UID", "Owner", "RX", "TX"], [[u, who(u), fmt_bytes(a["rx_bytes"]), fmt_bytes(a["tx_bytes"])] for u, a in top])
    body += "\n\n" + ctx.render_items(list(items.values()), specs)
    ctx.data["network"] = {"interfaces": ifaces, "interface_stats": dev, "routes_v4": items["route4"].parsed, "routes_v6": items["route6"].parsed, "rules": rules,
                           "neighbours": neigh, "dns": {"connectivity": dns, "props": dns_props, "private_dns": private_dns}, "proxy": proxy,
                           "tunnels": tunnels, "wifi": wifi, "bonded_bluetooth": bt, "sockets": socks, "unix_sockets": len(unix),
                           "uid_accounting": {str(k): v for k, v in uid_acct.items()}}
    ctx.add("Network", body)
