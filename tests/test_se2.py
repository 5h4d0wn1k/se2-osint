#!/usr/bin/env python3
"""Offline, fixture-based unit tests for SE2 OSINT Lab Framework."""

import json
import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from se2_cli import (
    LabGuard, OsintError, SyntheticBank, DnsResolver, WhoisClient,
    UrlEnumerator, EmailHarvester, EntityGraph, OsintEngine, WATERMARK,
)


class _FixtureWhoisServer(threading.Thread):
    """In-process WHOIS-like server on 127.0.0.1 (offline)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(5)
        self.port = self.srv.getsockname()[1]

    def run(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            with conn:
                data = conn.recv(1024).decode().strip()
                if not data:
                    continue
                conn.sendall(f"fixture WHOIS {data}\nStatus: fixture\n".encode())


class TestLabGuard(unittest.TestCase):
    def test_requires_lab_root(self):
        with self.assertRaises(OsintError):
            LabGuard(None)

    def test_requires_own_target(self):
        with self.assertRaises(OsintError):
            LabGuard("/tmp/x", target_org="EvilCorp")

    def test_refuses_real_email(self):
        g = LabGuard("/tmp/x")
        with self.assertRaises(OsintError):
            g.refuse_real(email="real.user@gmail.com")

    def test_allows_example_email(self):
        g = LabGuard("/tmp/x")
        g.refuse_real(email="ada@example.com")

    def test_refuses_real_domain(self):
        g = LabGuard("/tmp/x")
        with self.assertRaises(OsintError):
            g.refuse_real(domain="dropbox.com")

    def test_refuses_non_rfc_ip(self):
        g = LabGuard("/tmp/x")
        with self.assertRaises(OsintError):
            g.refuse_real(ip_text="8.8.8.8")


class TestSyntheticBank(unittest.TestCase):
    def test_persona_is_example_com(self):
        p = SyntheticBank(seed=1).persona(0)
        self.assertTrue(p["email"].endswith("@example.com"))

    def test_ip_in_rfc5737(self):
        import ipaddress
        ip = ipaddress.ip_address(SyntheticBank().rfc5737_ip())
        self.assertTrue(any(ip in ipaddress.ip_network(n) for n in
                            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")))


class TestDnsResolver(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp()
        self.guard = LabGuard(self.tmp)

    def test_fixture_resolution(self):
        r = DnsResolver(self.guard).resolve("lab-router.example")
        self.assertEqual(r["ip"], "192.0.2.1")
        self.assertEqual(r["mode"], "fixture")

    def test_refuses_real_hostname(self):
        with self.assertRaises(OsintError):
            DnsResolver(self.guard).resolve("github.com")


class TestWhoisClient(unittest.TestCase):
    def test_offline_whois(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        guard = LabGuard(tmp)
        server = _FixtureWhoisServer()
        server.start()
        try:
            r = WhoisClient(guard, host="127.0.0.1", port=server.port).query("mail.example")
        finally:
            server.srv.close()
        self.assertIn("fixture WHOIS", r["record"])
        self.assertIn(WATERMARK, r["record"])


class TestUrlEnumerator(unittest.TestCase):
    def test_candidates(self):
        urls = UrlEnumerator("example.com").candidates()
        self.assertGreater(len(urls), 10)
        self.assertTrue(all("example.com" in u for u in urls))


class TestEmailHarvester(unittest.TestCase):
    def test_filters_real_emails(self):
        g = LabGuard(os.getcwd())
        text = "contact joe@gmail.com or ada@example.com or dropbox.com"
        found = EmailHarvester(g).from_text(text)
        self.assertEqual(found, ["ada@example.com"])


class TestEntityGraph(unittest.TestCase):
    def test_structure(self):
        g = EntityGraph()
        g.add("email", "ada@example.com")
        g.relate("ada", "ada@example.com", "uses")
        d = g.to_dict()
        self.assertEqual(len(d["nodes"]), 1)
        self.assertEqual(len(d["edges"]), 1)
        self.assertEqual(d["watermark"], WATERMARK)


class TestEngine(unittest.TestCase):
    def test_run_is_synthetic_and_writes_report(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        guard = LabGuard(tmp)
        report = OsintEngine(guard).run(seed=7)
        self.assertEqual(report["watermark"], WATERMARK)
        self.assertTrue(report["edge_count"] > 0)
        self.assertTrue(os.path.exists(report["report_path"]))
        for t in report["targets"]:
            self.assertTrue(t["email"].endswith("@example.com"))


if __name__ == "__main__":
    unittest.main()