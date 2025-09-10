# API-Security-Testing-Framework
API Security Testing Framework
A powerful and stealthy API security testing tool designed to identify vulnerabilities in REST and GraphQL APIs with advanced evasion techniques and comprehensive testing capabilities.

Features
Multi-API Support: Comprehensive testing for both REST and GraphQL APIs

Stealth Technology: Advanced evasion techniques with configurable stealth levels

Authentication Bypass Testing: Multiple techniques to test for auth vulnerabilities

Endpoint Discovery: Intelligent discovery of API endpoints with wordlist support

Vulnerability Assessment: Tests for SQL injection, JWT weaknesses, GraphQL introspection, and more

OpenAPI/Swagger Integration: Automatic parsing of API documentation

Rate Limit Testing: Detection and analysis of rate limiting mechanisms

Parallel Testing: Multi-threaded execution for faster scanning

Comprehensive Reporting: Detailed vulnerability reports with evidence

Installation
Prerequisites
Python 3.7+

pip (Python package manager)

Install from Source
bash
git clone https://github.com/VastScientist69/API-Security-Testing-Framework.git
cd API-Security-Testing-Framework
pip install -r requirements.txt
Required Dependencies
The framework requires the following Python packages:

requests

PyYAML

fake-useragent

cryptography

Usage
Basic Syntax
bash
python api_security_tester.py <target_url> [options]
Examples
Basic scan with default settings:

bash
python api_security_tester.py https://api.example.com
Stealthy scan with custom wordlist:

bash
python api_security_tester.py https://api.example.com -w paths.txt -s 2
Scan with custom headers and proxy:

bash
python api_security_tester.py https://api.example.com -H "Authorization: Bearer token123" -H "X-API-Key: key456" -x http://proxy:8080
Comprehensive scan with full output:

bash
python api_security_tester.py https://api.example.com -t 10 -T 15 -s 0 -o detailed_report.txt
Command Line Options
Option	Description	Default
target	Target URL to test (required)	-
-w, --wordlist	Wordlist for endpoint discovery	Built-in list
-H, --header	Add custom headers (repeatable)	None
-t, --threads	Number of threads for parallel testing	5
-T, --timeout	Request timeout in seconds	10
-s, --stealth	Stealth level (0=Normal, 1=Medium, 2=High)	2
-x, --proxy	Proxy to use for requests	None
-o, --output	Output file for report	api_security_report.txt
Stealth Levels
The framework offers three configurable stealth levels:

Level 0: Normal
No request delays

All payloads tested

Verbose output

Recommended for internal testing

Level 1: Medium
Moderate request delays (0.5-2 seconds)

Filtered payload selection

Reduced output verbosity

Balanced approach for most testing scenarios

Level 2: High (Default)
Randomized request delays

Minimal payload testing

Stealth headers and IP spoofing

Maximum evasion for sensitive environments

Testing Capabilities
Authentication Bypass Tests
Missing authentication headers

Malformed tokens and signatures

Alternative header injection (X-Original-URL, X-Rewrite-URL)

Case variation attacks

Referer and Origin header spoofing

SQL Injection Tests
Boolean-based SQLi payloads

Time-based blind SQLi

UNION-based attacks

Error-based detection

Parameter pollution techniques

GraphQL-Specific Tests
Introspection query detection

Schema information disclosure

Authentication bypass attempts

Query and mutation testing

JWT Vulnerability Tests
"none" algorithm vulnerability

Weak secret testing

Empty signature verification

Token parsing and validation

API Endpoint Discovery
Common API path enumeration

Swagger/OpenAPI documentation detection

REST parameter pattern recognition

GraphQL endpoint identification

Payload Files
The framework supports custom payload files for advanced testing:

SQL Injection Payloads (sql_payloads.txt)
text
# Common SQL injection payloads
' OR '1'='1
' UNION SELECT NULL--
'; DROP TABLE users; --
XSS Payloads (xss_payloads.txt)
text
# XSS testing payloads
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
Path Traversal Payloads (path_traversal_payloads.txt)
text
# Path traversal payloads
../../../../etc/passwd
..\..\..\..\windows\system32\drivers\etc\hosts
Bypass Payloads (bypass_payloads.txt)
text
# Authentication bypass payloads
admin
true
false
null
Report Format
The tool generates comprehensive reports including:

Target information and scan timestamp

Discovered endpoints with status codes

Identified vulnerabilities with details

Request/response evidence

Severity assessment

Sample report excerpt:

text
API Security Testing Report
==================================================
Target: https://api.example.com
Test date: 2023-11-15 14:30:22
Stealth level: 2
Endpoints discovered: 47
Vulnerabilities found: 3

VULNERABILITIES:

[1] Authentication Bypass
  endpoint: https://api.example.com/api/admin
  technique: X-Original-URL header
  status_code: 200
  response_length: 1245

[2] GraphQL Introspection Enabled
  endpoint: https://api.example.com/graphql
  severity: Medium
  details: GraphQL introspection is enabled, exposing schema information
Ethical Use
This tool is designed for:

Security professionals conducting authorized assessments

Developers testing their own applications

Educational purposes in controlled environments

Important: Always obtain proper authorization before testing any system. Unauthorized testing may be illegal and unethical.

Disclaimer
This tool is provided for educational and authorized testing purposes only. The developers are not responsible for any misuse or damage caused by this tool. Users are solely responsible for ensuring they have proper authorization before using this tool against any systems.

Contributing
Contributions are welcome! Please feel free to submit pull requests, open issues, or suggest new features.

Fork the repository

Create your feature branch (git checkout -b feature/amazing-feature)

Commit your changes (git commit -m 'Add amazing feature')

Push to the branch (git push origin feature/amazing-feature)

Open a Pull Request

License
This project is licensed under the MIT License - see the LICENSE file for details.

Support
For issues, questions, or suggestions:

Check the existing GitHub issues

Create a new issue with detailed information

Provide target examples (if possible) and error messages

Acknowledgments
Inspired by various open-source security tools

Community contributors and testers

Security researchers who advance API security knowledge

