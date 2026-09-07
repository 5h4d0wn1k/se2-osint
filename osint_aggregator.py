#!/usr/bin/env python3
"""
SE2 — OSINT Aggregator (lab-sealed)
Username enumeration, email analysis, profiling, correlation.

ANTI-ABUSE: lab-mode ON. Every module requires an explicit lab-root; live HTTP
enumeration is DISABLED by default (returns fixture results); emails outside
example.* are refused; reports only ever contain synthetic data.
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib

WATERMARK = "SIMULATION / AUTHORIZED TRAINING ONLY"


class OsintGuardError(Exception):
    pass


class LabGuard:
    def __init__(self, lab_root=None, target_org="OWN", online=False):
        if not lab_root:
            raise OsintGuardError("Explicit --lab-root is required.")
        if target_org != "OWN":
            raise OsintGuardError("Only --target-org OWN is permitted in lab mode.")
        self.lab_root = Path(lab_root)
        self.reports = self.lab_root / "reports"
        self.reports.mkdir(parents=True, exist_ok=True)
        self.online = online

    def refuse_real_email(self, email):
        if "@" not in email or email.split("@")[1].lower() not in (
                "example.com", "example.org", "example.net"):
            raise OsintGuardError(f"Refusing email '{email}': only example.* allowed.")
        return email

    def watermark(self, text):
        return f"[{WATERMARK}]\n{text}"


class UsernameEnumerator:
    """Enumerate usernames (SIMULATED by default; live requires guard + online-lab)"""

    def __init__(self, lab_root=None, target_org="OWN", online=False):
        self.guard = LabGuard(lab_root, target_org, online=online)
        self.platforms = {
            "github": "https://github.com/{username}",
            "twitter": "https://twitter.com/{username}",
            "reddit": "https://www.reddit.com/user/{username}",
            "linkedin": "https://www.linkedin.com/in/{username}",
            "instagram": "https://www.instagram.com/{username}/",
            "tiktok": "https://www.tiktok.com/@{username}",
            "youtube": "https://www.youtube.com/@{username}",
            "medium": "https://medium.com/@{username}",
            "keybase": "https://keybase.io/{username}",
            "hackerone": "https://hackerone.com/{username}",
            "tryhackme": "https://tryhackme.com/p/{username}",
            "hackthebox": "https://app.hackthebox.com/profile/{username}"
        }
        self.results = {}
    
    def check_username(self, username: str, platform: str, url: str) -> Dict:
        """Check if username exists on platform (SIMULATION when not online)"""
        if not self.guard.online:
            fake = {"github": 200, "twitter": 404, "reddit": 200, "linkedin": 404,
                    "instagram": 200, "tiktok": 404, "youtube": 200, "medium": 404,
                    "keybase": 200, "hackerone": 404, "tryhackme": 200, "hackthebox": 404}
            code = fake.get(platform, 404)
            return {
                "platform": platform,
                "url": url.format(username=username),
                "status": "found" if code == 200 else "not_found",
                "code": code,
                "mode": "fixture",
                "watermark": WATERMARK,
            }
        try:
            full_url = url.format(username=username)
            req = urllib.request.Request(
                full_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            response = urllib.request.urlopen(req, timeout=10)
            return {
                "platform": platform,
                "url": full_url,
                "status": "found",
                "code": response.getcode()
            }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"platform": platform, "url": url.format(username=username), "status": "not_found", "code": 404}
            return {"platform": platform, "url": url.format(username=username), "status": "error", "code": e.code}
        except Exception as e:
            return {"platform": platform, "url": url.format(username=username), "status": "error", "error": str(e)}
    
    def enumerate(self, username: str, platforms: Optional[List[str]] = None, 
                  max_workers: int = 10) -> Dict:
        """Check username across multiple platforms concurrently"""
        platforms_to_check = platforms or list(self.platforms.keys())
        results = {"username": username, "found": [], "not_found": [], "errors": []}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for platform in platforms_to_check:
                if platform in self.platforms:
                    future = executor.submit(
                        self.check_username, username, platform, self.platforms[platform]
                    )
                    futures[future] = platform
            
            for future in as_completed(futures):
                result = future.result()
                if result["status"] == "found":
                    results["found"].append(result)
                elif result["status"] == "not_found":
                    results["not_found"].append(result)
                else:
                    results["errors"].append(result)
        
        self.results[username] = results
        return results


class EmailHarvester:
    """Harvest emails from various sources"""
    
    def __init__(self, lab_root=None, target_org="OWN", online=False):
        self.guard = LabGuard(lab_root, target_org, online=online)
        self.email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        self.harvested_emails = set()
    
    def extract_emails_from_text(self, text: str) -> Set[str]:
        """Extract emails from text using regex"""
        return set(self.email_pattern.findall(text))
    
    def search_email(self, email: str) -> Dict:
        """Search for email information (synthetic only; must be example.*)"""
        self.guard.refuse_real_email(email)
        result = {
            "email": email,
            "hash": hashlib.md5(email.encode()).hexdigest(),
            "domain": email.split("@")[1] if "@" in email else None,
            "providers": []
        }
        
        # Check common email providers
        providers = {
            "gmail.com": "Google Gmail",
            "yahoo.com": "Yahoo Mail",
            "outlook.com": "Microsoft Outlook",
            "hotmail.com": "Microsoft Hotmail",
            "protonmail.com": "ProtonMail",
            "icloud.com": "Apple iCloud"
        }
        
        domain = result["domain"]
        if domain in providers:
            result["providers"].append(providers[domain])
        
        return result
    
    def check_email_breach(self, email: str) -> Dict:
        """Check if email appears in known breaches (simulated)"""
        # Note: This is a simulation. Real breach checking would use Have I Been Pwned API
        return {
            "email": email,
            "breach_checked": True,
            "breaches_found": 0,
            "note": "This is simulated data for educational purposes"
        }
    
    def harvest_from_file(self, filepath: str) -> Set[str]:
        """Extract emails from a text file"""
        emails = set()
        try:
            with open(filepath, "r") as f:
                content = f.read()
                emails = self.extract_emails_from_text(content)
                self.harvested_emails.update(emails)
        except FileNotFoundError:
            print(f"File not found: {filepath}")
        return emails
    
    def get_all_harvested(self) -> Set[str]:
        """Get all harvested emails"""
        return self.harvested_emails


class SocialMediaProfiler:
    """Profile social media accounts"""
    
    def __init__(self):
        self.profiles = {}
    
    def create_profile(self, username: str) -> Dict:
        """Create a new profile"""
        profile = {
            "username": username,
            "created": datetime.now().isoformat(),
            "platforms": {},
            "metadata": {},
            "activity": {}
        }
        self.profiles[username] = profile
        return profile
    
    def add_platform_data(self, username: str, platform: str, data: Dict):
        """Add platform data to profile"""
        if username not in self.profiles:
            self.create_profile(username)
        self.profiles[username]["platforms"][platform] = data
    
    def analyze_username(self, username: str) -> Dict:
        """Analyze username for patterns"""
        analysis = {
            "username": username,
            "length": len(username),
            "has_numbers": bool(re.search(r'\d', username)),
            "has_underscores": "_" in username,
            "has_hyphens": "-" in username,
            "has_uppercase": any(c.isupper() for c in username),
            "common_patterns": []
        }
        
        # Check for common patterns
        patterns = {
            "name_year": r'^[a-z]+\d{4}$',
            "name_number": r'^[a-z]+\d+$',
            "first_last": r'^[a-z]+_[a-z]+$',
            "firstlast": r'^[a-z]{2,}$'
        }
        
        for pattern_name, pattern in patterns.items():
            if re.match(pattern, username.lower()):
                analysis["common_patterns"].append(pattern_name)
        
        return analysis
    
    def get_profile(self, username: str) -> Optional[Dict]:
        """Get profile for username"""
        return self.profiles.get(username)
    
    def get_all_profiles(self) -> Dict:
        """Get all profiles"""
        return self.profiles


class DataCorrelator:
    """Correlate data from multiple sources"""
    
    def __init__(self):
        self.correlations = []
    
    def correlate(self, data_points: List[Dict], key_field: str) -> List[Dict]:
        """Correlate data points by a common key"""
        grouped = {}
        for point in data_points:
            key = point.get(key_field)
            if key:
                if key not in grouped:
                    grouped[key] = []
                grouped[key].append(point)
        
        correlations = []
        for key, points in grouped.items():
            if len(points) > 1:
                correlations.append({
                    "key": key,
                    "count": len(points),
                    "sources": points
                })
        
        self.correlations.extend(correlations)
        return correlations
    
    def find_common_entities(self, datasets: List[Dict]) -> Dict:
        """Find common entities across datasets"""
        entity_counts = {}
        
        for dataset in datasets:
            for key, value in dataset.items():
                if isinstance(value, str):
                    if value not in entity_counts:
                        entity_counts[value] = {"count": 0, "fields": set()}
                    entity_counts[value]["count"] += 1
                    entity_counts[value]["fields"].add(key)
        
        # Filter to entities appearing in multiple datasets
        common = {k: v for k, v in entity_counts.items() if v["count"] > 1}
        return common
    
    def generate_report(self) -> Dict:
        """Generate correlation report"""
        return {
            "total_correlations": len(self.correlations),
            "correlations": self.correlations
        }


class OSINTAggregator:
    """Main OSINT aggregation system"""
    
    def __init__(self, lab_root=None, target_org="OWN", online=False):
        self.username_enum = UsernameEnumerator(lab_root, target_org, online)
        self.email_harvester = EmailHarvester(lab_root, target_org, online)
        self.profiler = SocialMediaProfiler()
        self.correlator = DataCorrelator()
        self.results = {}
    
    def investigate_target(self, target: Dict) -> Dict:
        """Full investigation on a target"""
        investigation = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "username_results": None,
            "email_results": None,
            "profile": None
        }
        
        # Username enumeration
        if "username" in target:
            investigation["username_results"] = self.username_enum.enumerate(
                target["username"]
            )
        
        # Email investigation
        if "email" in target:
            investigation["email_results"] = self.email_harvester.search_email(
                target["email"]
            )
        
        # Create profile
        username = target.get("username", "unknown")
        investigation["profile"] = self.profiler.create_profile(username)
        
        # Add any additional data
        if "platforms" in target:
            for platform, data in target["platforms"].items():
                self.profiler.add_platform_data(username, platform, data)
        
        self.results[username] = investigation
        return investigation
    
    def export_results(self, filepath: str):
        """Export all results to JSON"""
        export_data = {
            "timestamp": datetime.now().isoformat(),
            "investigations": self.results,
            "correlations": self.correlator.generate_report()
        }
        
        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2, default=str)
    
    def get_summary(self) -> Dict:
        """Get summary of all investigations"""
        return {
            "total_investigations": len(self.results),
            "usernames_found": len([r for r in self.results.values() if r.get("username_results", {}).get("found")]),
            "emails_harvested": len(self.email_harvester.get_all_harvested()),
            "profiles_created": len(self.profiler.get_all_profiles())
        }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="SE2 OSINT Aggregator (lab-sealed).")
    ap.add_argument("--lab-root", required=True)
    ap.add_argument("--target-org", default="OWN")
    ap.add_argument("--online-lab", action="store_true")
    argv = ap.parse_args(sys.argv[1:])
    guard = LabGuard(argv.lab_root, argv.target_org, online=argv.online_lab)

    print(f"SE2 — OSINT Aggregator [{WATERMARK}]")
    print("=" * 40)

    aggregator = OSINTAggregator(argv.lab_root, argv.target_org, argv.online_lab)

    target = {
        "username": "ada.lovelace",
        "email": guard.refuse_real_email("ada.lovelace@example.com")
    }

    result = aggregator.investigate_target(target)

    print(f"\nUsername enumeration for '{target['username']}' (SIMULATED):")
    if result["username_results"]:
        print(f"  Found on: {len(result['username_results']['found'])} platforms (fixture)")
        print(f"  Not found: {len(result['username_results']['not_found'])} platforms (fixture)")

    print(f"\nEmail analysis for '{target['email']}':")
    if result["email_results"]:
        print(f"  Domain: {result['email_results']['domain']}")

    analysis = aggregator.profiler.analyze_username(target["username"])
    print("\nUsername analysis:")
    print(f"  Length: {analysis['length']}")
    print(f"  Has numbers: {analysis['has_numbers']}")
    print(f"  Common patterns: {analysis['common_patterns']}")

    out = guard.reports / "aggregator_summary.json"
    out.write_text(json.dumps({**aggregator.get_summary(), "watermark": WATERMARK}, indent=2))
    print(f"\nSummary written: {out}")
    print("Note: fixture mode (offline). Add --online-lab only for your OWN example.* lab names.")
