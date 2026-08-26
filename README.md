# SE2 — OSINT Aggregator

Username enumeration, email harvesting, social media profiling, data correlation.

## Overview

This project implements an Open Source Intelligence (OSINT) aggregation system that:
- Enumerates usernames across multiple platforms concurrently
- Harvests and analyzes email addresses
- Creates comprehensive social media profiles
- Correlates data from multiple sources
- Generates investigation reports

## Features

- **Username Enumeration**: Check 12+ platforms for username existence
- **Email Harvesting**: Extract emails from files and validate format
- **Social Media Profiling**: Build comprehensive target profiles
- **Data Correlation**: Find connections between different data points
- **Concurrent Processing**: Fast multi-threaded platform checks

## Installation

No external dependencies required — uses Python standard library only.

```bash
python3 osint_aggregator.py
```

## Usage

### Username Enumeration
```python
from osint_aggregator import UsernameEnumerator

enumerator = UsernameEnumerator()
results = enumerator.enumerate("target_username")
print(f"Found on: {len(results['found'])} platforms")
```

### Email Investigation
```python
from osint_aggregator import EmailHarvester

harvester = EmailHarvester()
info = harvester.search_email("target@example.com")
print(f"Domain: {info['domain']}")
```

### Full Investigation
```python
from osint_aggregator import OSINTAggregator

aggregator = OSINTAggregator()
result = aggregator.investigate_target({
    "username": "target_user",
    "email": "target@example.com"
})
aggregator.export_results("results.json")
```

### Username Analysis
```python
from osint_aggregator import SocialMediaProfiler

profiler = SocialMediaProfiler()
analysis = profiler.analyze_username("john_doe_123")
print(f"Patterns: {analysis['common_patterns']}")
```

## Example Output

```
SE2 — OSINT Aggregator
========================================

[*] Running sample investigation...

Username enumeration for 'testuser':
  Found on: 3 platforms
  Not found: 9 platforms

Email analysis for 'test@example.com':
  Domain: example.com

Username analysis:
  Length: 8
  Has numbers: True
  Common patterns: ['name_number']
```

## Supported Platforms

- GitHub, Twitter, Reddit, LinkedIn
- Instagram, TikTok, YouTube
- Medium, Keybase, HackerOne
- TryHackMe, HackTheBox

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
