# SE2 — OSINT Lab Framework

Synthetic open-source-intelligence pipelines for **authorized training** on your own
data. Every output uses only RFC5737 IPs, `example.com` addresses and synthetic
personas; no live scraping runs in tests or the default offline mode. Live socket
resolvers are gated behind `--online-lab` and restricted to your own `.example`
/ `.test` lab names.

## Features

- **DNS resolver pipeline** — stdlib `socket`-based, fixture mode by default; live
  path gated by `--online-lab` and restricted to lab TLDs.
- **WHOIS client** — raw stdlib socket WHOIS query against a configurable local
  server (127.0.0.1 in labs/tests); offline fixture demo included.
- **Search-engine-style URL enumeration** — candidate URL generator for a synthetic
  seed domain (`example.com`).
- **Email harvester** — regex extraction that **refuses** anything outside
  `example.*`.
- **Entity graph builder** — JSON graph of personas → emails → RFC5737 IPs.
- **Reports** — JSON written under `lab-root/reports/`, watermarked.

## IMPORTANT: Read before use.

Provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission and a scoped agreement for any
  investigation.
- `--target-org` is locked to `OWN`; other targets are refused in lab mode.
- This is a **synthetic-data** framework: real emails, real domains, and non-RFC5737
  IP addresses are refused.
- Requests to remove these safeguards will be refused.

### Anti-Abuse Safeguards
- Every run requires an explicit `--lab-root`.
- Offline fixtures are the default; live enumeration requires `--online-lab` **and**
  refuses real domains.
- All output (reports, records) carries the watermark
  "SIMULATION / AUTHORIZED TRAINING ONLY".

### Legal Framework
- **CFAA (18 U.S.C. § 1030)**, **Wiretap Act (18 U.S.C. § 2511)**, **state computer
  crime laws**, and **GDPR/CCPA** apply to data collection and access.
- Harvesting from unauthorized sources is illegal.

### Prohibited Use
- Collecting or storing real personal data.
- Probing organizations or people without authorization.
- Using results to further an attack.

### No Warranty
Provided "AS IS" without warranty. Author accepts no liability for misuse.

### Responsible Disclosure
Report findings privately, allow remediation time, never publish raw personal data.

## Live Lab Test Plan

1. `python3 se2_cli.py --lab-root ./lab --demo` → exit 0, synthetic report in `./lab/reports/`.
2. `python3 se2_cli.py --lab-root ./lab --whois-demo` → offline WHOIS fixture demo on 127.0.0.1.
3. `python3 se2_cli.py --lab-root ./lab --enumerate-urls` → candidate URL list.
4. `python3 osint_aggregator.py --lab-root ./lab` → legacy aggregator, fixture mode.
5. Negative: `python3 se2_cli.py --lab-root ./lab --target-org EvilCorp` must exit non-zero.
6. `python -m unittest discover -s tests` → 15 offline tests pass.

## Metrics

- Synthetic personas: 12 (seeded, deterministic).
- DNS fixture map: 4 lab records (RFC5737 IPs only).
- URL candidates per seed domain: 42.
- Test count: 15 (no network calls; WHOIS uses in-process 127.0.0.1 server).

## Usage

```bash
python3 se2_cli.py --lab-root ./lab --demo
python3 se2_cli.py --lab-root ./lab --whois-demo
python3 se2_cli.py --lab-root ./lab --online-lab   # only your OWN .example lab names
```

## License

MIT