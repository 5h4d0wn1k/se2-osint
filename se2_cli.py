#!/usr/bin/env python3
"""
SE2 — OSINT Lab Framework
Synthetic open-source-intelligence pipelines for authorized training.

Anti-abuse by default:
  * requires explicit --lab-root and --target-org OWN
  * offline by default (fixtures); live socket resolvers gated behind --online-lab
  * only synthetic personas, example.com addresses, RFC5737 IP ranges
  * all reports written under lab-root/reports/ and watermarked
"""

import argparse
import ipaddress
import json
import os
import random
import re
import socket
import sys
import threading
from datetime import datetime
from pathlib import Path

WATERMARK = "SIMULATION / AUTHORIZED TRAINING ONLY"
ALLOWED_TLDS = (".example", ".internal", ".lab", ".invalid")
RFC5737 = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
RFC5737_NETS = [ipaddress.ip_network(n) for n in RFC5737]

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
DOMAIN_RE = re.compile(r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                       r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$", re.IGNORECASE)


class OsintError(Exception):
    pass


class LabGuard:
    def __init__(self, lab_root, target_org="OWN", online=False):
        if not lab_root:
            raise OsintError("Explicit --lab-root is required.")
        if target_org != "OWN":
            raise OsintError("Only --target-org OWN is permitted in lab mode.")
        self.lab_root = Path(lab_root)
        self.reports = self.lab_root / "reports"
        self.reports.mkdir(parents=True, exist_ok=True)
        self.online = online

    def refuse_real(self, email=None, domain=None, ip_text=None):
        if email:
            if "@" in email and not email.lower().endswith("@" + email.split("@")[1].lower()):
                pass
            if "@" not in email or email.split("@")[1].lower() not in ("example.com", "example.org",
                                                                       "example.net", "example.edu"):
                raise OsintError(f"Refusing email '{email}': only example.* is allowed.")
        if domain:
            if not domain.lower().endswith(ALLOWED_TLDS):
                raise OsintError(f"Refusing domain '{domain}': only {ALLOWED_TLDS} are allowed.")
        if ip_text:
            ip = ipaddress.ip_address(ip_text)
            if not any(ip in net for net in RFC5737_NETS) and not ip.is_loopback:
                raise OsintError(f"Refusing IP '{ip_text}': only RFC5737 ranges are allowed.")

    def watermarked(self, text):
        return f"[{WATERMARK}]\n{text}"


class SyntheticBank:
    """Deterministic synthetic personas, emails, domains, IPs (seeded)."""

    NAMES = ["Ada Lovelace", "Grace Hopper", "Alan Turing", "Katherine Johnson",
             "Margaret Hamilton", "Barbara Liskov", "Edsger Dijkstra", "Ruchi Sanghvi",
             "Linus Torvalds", "Radia Perlman", "Edith Clarke", "Shafi Goldwasser"]

    def __init__(self, seed=42):
        self.rng = random.Random(seed)

    def persona(self, idx=0):
        name = self.NAMES[idx % len(self.NAMES)]
        first, last = name.lower().split()
        username = f"{first}.{last}"
        return {
            "name": name,
            "username": username,
            "email": f"{first}.{last}@example.com",
            "domain": "example.com",
            "role": self.rng.choice(["engineer", "manager", "support", "finance", "executive"]),
        }

    def rfc5737_ip(self):
        return str(self.rng.choice(RFC5737_NETS).network_address + self.rng.randint(1, 250))

    def fake_page_path(self):
        return "/" + self.rng.choice(["portal", "login", "status", "vpn", "hr", "wiki"]) + ".html"


class DnsResolver:
    """DNS lookups via stdlib socket. Offline mode returns fixture-style records.

    The online path is only ever used against your OWN .example lab names.
    """

    def __init__(self, guard):
        self.guard = guard
        self._fixture = {
            "lab-router.example": "192.0.2.1",
            "mail.example": "198.51.100.10",
            "www.example": "203.0.113.25",
            "vpn.example": "192.0.2.50",
        }

    def resolve(self, hostname):
        self.guard.refuse_real(domain=hostname)
        if not self.guard.online:
            if hostname in self._fixture:
                return {"hostname": hostname, "ip": self._fixture[hostname], "mode": "fixture"}
            return {"hostname": hostname, "ip": None, "mode": "unresolved-fixture"}
        try:
            ip = socket.gethostbyname(hostname)
            return {"hostname": hostname, "ip": ip, "mode": "live"}
        except OSError as e:
            return {"hostname": hostname, "ip": None, "mode": f"error:{e}"}


class WhoisClient:
    """WHOIS-like query via raw stdlib socket to a configurable server (127.0.0.1 in labs/tests)."""

    def __init__(self, guard, host="127.0.0.1", port=4343, timeout=3):
        self.guard = guard
        self.host = host
        self.port = port
        self.timeout = timeout

    def query(self, domain):
        self.guard.refuse_real(domain=domain)
        try:
            s = socket.create_connection((self.host, self.port), timeout=self.timeout)
            try:
                s.settimeout(self.timeout)
                req = f"whois {domain}\r\n".encode()
                s.sendall(req)
                chunks = []
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
            finally:
                s.close()
            text = b"".join(chunks).decode("utf-8", "replace")
            return {"domain": domain, "whois_server": f"{self.host}:{self.port}",
                    "record": self.guard.watermarked(text), "raw": text}
        except OSError as e:
            return {"domain": domain, "whois_server": f"{self.host}:{self.port}",
                    "record": "", "error": str(e)}


class UrlEnumerator:
    """Search-engine-style candidate URL generation for a synthetic seed domain."""

    WORDLIST = ["admin", "login", "vpn", "portal", "hr", "finance", "config",
                "backup", "uploads", "api", "docs", "wiki", "status", "support"]

    def __init__(self, seed_domain="example.com"):
        self.seed_domain = seed_domain

    def candidates(self):
        out = []
        for word in self.WORDLIST:
            out.append(f"https://{self.seed_domain}/{word}")
            out.append(f"https://{self.seed_domain}/{word}.php")
            out.append(f"https://{self.seed_domain}/{word}/index.html")
        return out


class EmailHarvester:
    """Harvest e-mails from provided synthetic corpus files (example.com only)."""

    def __init__(self, guard):
        self.guard = guard

    def from_text(self, text):
        found = set()
        for m in EMAIL_RE.findall(text):
            try:
                self.guard.refuse_real(email=m)
                found.add(m.lower())
            except OsintError:
                continue
        return sorted(found)


class EntityGraph:
    """Builds a JSON entity graph from harvested synthetic entities."""

    def __init__(self):
        self.nodes = []
        self.edges = []

    def add(self, node_type, value, props=None):
        self.nodes.append({"type": node_type, "value": value, **(props or {})})

    def relate(self, a, b, reltype, weight=1.0):
        self.edges.append({"source": a, "target": b, "relation": reltype, "weight": weight})

    def to_dict(self):
        return {"watermark": WATERMARK, "nodes": self.nodes, "edges": self.edges,
                "generated": datetime.now().isoformat()}


class OsintEngine:
    """Composite offline OSINT pipeline."""

    def __init__(self, guard):
        self.guard = guard
        self.bank = SyntheticBank()
        self.dns = DnsResolver(guard)
        self.url_enum = UrlEnumerator("example.com")

    def run(self, seed=42):
        self.bank = SyntheticBank(seed)
        report = {"watermark": WATERMARK,
                  "generated": datetime.now().isoformat(),
                  "targets": [], "dns_map": [], "url_candidates":
                  len(self.url_enum.candidates()), "graph": None}

        for i in range(4):
            p = self.bank.persona(i)
            report["targets"].append(p)

        for host in ("lab-router.example", "mail.example", "www.example", "vpn.example"):
            report["dns_map"].append(self.dns.resolve(host))

        graph = EntityGraph()
        for p in report["targets"]:
            graph.add("persona", p["name"], {"email": p["email"], "username": p["username"]})
            graph.add("email", p["email"])
            ip = self.bank.rfc5737_ip()
            graph.add("ip", ip, {"rfc5737": True})
            graph.relate(p["name"], p["email"], "uses")
            graph.relate(p["email"], ip, "seen_from")
        report["graph"] = graph.to_dict()

        report_path = self.guard.reports / "osint_report.json"
        report_path.write_text(json.dumps(report, indent=2))
        report["report_path"] = str(report_path)
        report["edge_count"] = len(report["graph"]["edges"])
        return report


def run_whois_demo(guard):
    """Offline WHOIS fixture demo via a tiny local in-process server."""

    class FixtureWhois(threading.Thread):
        def __init__(self):
            super().__init__(daemon=True)
            self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.srv.bind(("127.0.0.1", 0))
            self.srv.listen(5)
            self.port = self.srv.getsockname()[1]

        def run(self):
            self.srv.settimeout(4)
            while True:
                try:
                    conn, _ = self.srv.accept()
                except OSError:
                    return
                with conn:
                    data = conn.recv(1024).decode().strip()
                    if not data:
                        continue
                    conn.sendall(f"fixture WHOIS {data}\nRegistrar: Synthetic Labs\n"
                                 f"Domain: example\nStatus: fixture-only\n".encode())

    srv = FixtureWhois()
    srv.start()
    inputs = ("lab-router.example", "mail.example")
    client = WhoisClient(guard, host="127.0.0.1", port=srv.port)
    results = [client.query(d) for d in inputs]
    srv.srv.close()
    srv.join(timeout=3)
    return results


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(
        prog="se2-osint",
        description="Synthetic OSINT lab framework (authorized training only).")
    p.add_argument("--lab-root", required=True, help="Local lab folder (required).")
    p.add_argument("--target-org", default="OWN", help="Must be OWN in lab mode.")
    p.add_argument("--seed", type=int, default=42, help="Deterministic persona seed.")
    p.add_argument("--online-lab", action="store_true",
                   help="Allow live socket DNS/W.H.O.I.S against your own .example lab names.")
    p.add_argument("--whois-demo", action="store_true",
                   help="Run the offline W.H.O.I.S fixture demo on 127.0.0.1.")
    p.add_argument("--demo", action="store_true", help="Run the offline OSINT demo.")
    p.add_argument("--enumerate-urls", action="store_true",
                   help="Generate candidate URL list for synthetic seed domain.")
    args = p.parse_args(argv)

    guard = LabGuard(args.lab_root, args.target_org, online=args.online_lab)
    print(f"SE2 OSINT Lab Framework [{WATERMARK}]")
    print("=" * 60)

    if args.whois_demo:
        results = run_whois_demo(guard)
        for r in results:
            print(json.dumps(r, indent=2))
        print("\nWHOIS fixture demo complete (offline on 127.0.0.1).")
    elif args.enumerate_urls:
        urls = UrlEnumerator("example.com").candidates()
        print(f"Generated {len(urls)} candidate URLs for example.com (synthetic):")
        for u in urls[:8]:
            print("  ", u)
        print("  ...")
    else:
        report = OsintEngine(guard).run(args.seed)
        print(f"\nSynthetic targets profiled: {len(report['targets'])}")
        for t in report["targets"]:
            print(f"  {t['name']:<22} {t['email']:<28} {t['role']}")
        print(f"\nSurfaced DNS map (fixture): {len(report['dns_map'])} records")
        for d in report["dns_map"]:
            print(f"  {d['hostname']:<24} -> {d['ip']}")
        print(f"\nCandidate URLs generated: {report['url_candidates']}")
        print(f"Entity graph: {report['edge_count']} edges, "
              f"{len(report['graph']['nodes'])} nodes")
        print(f"Report written: {report['report_path']}")

    print("\nDemo complete (offline, synthetic only). Exit 0.")
    return 0


if __name__ == "__main__":
    sys.exit(main())