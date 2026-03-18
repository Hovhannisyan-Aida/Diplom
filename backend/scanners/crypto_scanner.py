from typing import List, Dict, Any
from scanners.base_scanner import BaseScanner
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
import hashlib
import re
import logging

logger = logging.getLogger(__name__)


class CryptoScanner(BaseScanner):

    def scan(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting Crypto scan for {self.target_url}")
        print(f"Starting Crypto scan for {self.target_url}", flush=True)

        parsed_url = urlparse(self.target_url)
        hostname = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)

        if parsed_url.scheme != 'https':
            self.add_vulnerability({
                "vuln_type": "cryptographic_failure",
                "severity": "high",
                "title": "HTTP Used Instead of HTTPS",
                "description": f"The website {self.target_url} is not using HTTPS. All data transmitted is unencrypted and vulnerable to interception.",
                "url": self.target_url,
                "recommendation": "Enable HTTPS with a valid SSL/TLS certificate. Redirect all HTTP traffic to HTTPS.",
                "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
            })

            response = self.make_request(self.target_url, allow_redirects=False)
            if response:
                location = response.headers.get("location", "")
                if response.status_code in (301, 302) and location.startswith("https://"):
                    print(f"HTTP redirects to HTTPS at {location}", flush=True)
                else:
                    self.add_vulnerability({
                        "vuln_type": "cryptographic_failure",
                        "severity": "medium",
                        "title": "No HTTP to HTTPS Redirect",
                        "description": "The server does not redirect HTTP traffic to HTTPS, allowing users to browse insecurely.",
                        "url": self.target_url,
                        "recommendation": "Configure the server to redirect all HTTP requests to HTTPS (301 redirect).",
                        "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    })

        else:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()

                        print(f"TLS version: {version}, cipher: {cipher}", flush=True)

                        if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                            self.add_vulnerability({
                                "vuln_type": "cryptographic_failure",
                                "severity": "high",
                                "title": f"Weak TLS Version: {version}",
                                "description": f"The server supports outdated TLS version {version}, which has known vulnerabilities.",
                                "url": self.target_url,
                                "recommendation": "Disable TLS 1.0, TLS 1.1, and all SSL versions. Use TLS 1.2 or TLS 1.3 only.",
                                "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                            })

                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
                        if cipher and any(weak in str(cipher) for weak in weak_ciphers):
                            self.add_vulnerability({
                                "vuln_type": "cryptographic_failure",
                                "severity": "medium",
                                "title": "Weak Cipher Suite",
                                "description": f"The server supports weak cipher suite: {cipher[0]}",
                                "url": self.target_url,
                                "recommendation": "Disable weak cipher suites. Use strong ciphers like AES-GCM.",
                                "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                            })

                        if cert:
                            expire_str = cert.get("notAfter", "")
                            if expire_str:
                                try:
                                    expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                                    days_left = (expire_date - datetime.utcnow()).days
                                    print(f"Certificate expires in {days_left} days", flush=True)
                                    if days_left < 0:
                                        self.add_vulnerability({
                                            "vuln_type": "cryptographic_failure",
                                            "severity": "critical",
                                            "title": "SSL Certificate Expired",
                                            "description": f"The SSL certificate expired {abs(days_left)} days ago on {expire_date.strftime('%Y-%m-%d')}.",
                                            "url": self.target_url,
                                            "recommendation": "Renew the SSL certificate immediately.",
                                            "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                                        })
                                    elif days_left < 30:
                                        self.add_vulnerability({
                                            "vuln_type": "cryptographic_failure",
                                            "severity": "medium",
                                            "title": "SSL Certificate Expiring Soon",
                                            "description": f"The SSL certificate expires in {days_left} days on {expire_date.strftime('%Y-%m-%d')}.",
                                            "url": self.target_url,
                                            "recommendation": "Renew the SSL certificate before it expires.",
                                            "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                                        })
                                except Exception as e:
                                    logger.warning(f"Could not parse cert expiry: {e}")

            except ssl.SSLCertVerificationError as e:
                err_str = str(e).lower()
                if "self signed" in err_str or "self-signed" in err_str or "unable to get local issuer" in err_str:
                    self.add_vulnerability({
                        "vuln_type": "cryptographic_failure",
                        "severity": "high",
                        "title": "Self-Signed SSL Certificate",
                        "description": "The server is using a self-signed certificate which is not trusted by browsers and vulnerable to MITM attacks.",
                        "url": self.target_url,
                        "recommendation": "Replace the self-signed certificate with one from a trusted Certificate Authority (e.g. Let's Encrypt).",
                        "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    })
                else:
                    self.add_vulnerability({
                        "vuln_type": "cryptographic_failure",
                        "severity": "critical",
                        "title": "SSL/TLS Certificate Error",
                        "description": f"SSL/TLS certificate validation failed: {str(e)}",
                        "url": self.target_url,
                        "recommendation": "Install a valid SSL/TLS certificate from a trusted Certificate Authority.",
                        "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    })
            except ssl.SSLError as e:
                self.add_vulnerability({
                    "vuln_type": "cryptographic_failure",
                    "severity": "critical",
                    "title": "SSL/TLS Error",
                    "description": f"SSL/TLS error: {str(e)}",
                    "url": self.target_url,
                    "recommendation": "Review and fix the SSL/TLS configuration.",
                    "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                })
            except socket.timeout:
                logger.warning(f"Timeout connecting to {hostname}:{port}")
            except Exception as e:
                logger.error(f"Crypto scan error: {str(e)}")

        response = self.make_request(self.target_url)
        if response:
            hsts = response.headers.get("strict-transport-security", "")
            if not hsts:
                self.add_vulnerability({
                    "vuln_type": "cryptographic_failure",
                    "severity": "medium",
                    "title": "Missing HSTS Header",
                    "description": "HTTP Strict Transport Security (HSTS) header is not set. This allows potential downgrade attacks.",
                    "url": self.target_url,
                    "recommendation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                })
                print(f"HSTS header missing on {self.target_url}", flush=True)
            else:
                print(f"HSTS header present: {hsts}", flush=True)

        self._check_weak_hashing()

        print(f"Crypto scan finished, found {len(self.results)} vulnerabilities", flush=True)
        return self.get_results()

    def _check_weak_hashing(self):
        from urllib.parse import parse_qs, urlparse as _parse

        md5_pattern = re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE)
        sha1_pattern = re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE)

        known_values = ["admin", "password", "123456", "test", "user", "guest"]
        known_hashes = {}
        for val in known_values:
            known_hashes[hashlib.md5(val.encode()).hexdigest()] = ("MD5", val)
            known_hashes[hashlib.sha1(val.encode()).hexdigest()] = ("SHA1", val)

        parsed = _parse(self.target_url)
        url_params = parse_qs(parsed.query)
        for param, values in url_params.items():
            for val in values:
                is_md5 = md5_pattern.fullmatch(val.strip())
                is_sha1 = sha1_pattern.fullmatch(val.strip())
                if is_md5 or is_sha1:
                    algo = "MD5" if is_md5 else "SHA1"
                    known = known_hashes.get(val.strip().lower())
                    description = (
                        f"URL parameter '{param}' contains an unsalted {algo} hash of the value '{known[1]}' ({val}). "
                        if known else
                        f"URL parameter '{param}' contains a value matching a {algo} hash pattern ({val}). "
                    )
                    description += f"{algo} produces the same hash for the same input with no salt, making it vulnerable to rainbow table attacks."
                    print(f"Hash in URL param '{param}': {val} ({algo})", flush=True)
                    self.add_vulnerability({
                        "vuln_type": "cryptographic_failure",
                        "severity": "critical" if known else "high",
                        "title": f"Weak Unsalted {algo} Hash in URL Parameter '{param}'",
                        "description": description,
                        "url": self.target_url,
                        "recommendation": f"Never use {algo} for passwords. Use bcrypt, Argon2, or PBKDF2 with a unique salt.",
                        "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    })
                    return

        response = self.make_request(self.target_url)
        if not response:
            return

        body = response.text
        cookies = response.cookies

        found_md5 = md5_pattern.findall(body)
        found_sha1 = sha1_pattern.findall(body)

        for h in found_md5 + found_sha1:
            if h.lower() in known_hashes:
                algo, original = known_hashes[h.lower()]
                print(f"Unsalted {algo} hash found in response: {h} = '{original}'", flush=True)
                self.add_vulnerability({
                    "vuln_type": "cryptographic_failure",
                    "severity": "critical",
                    "title": f"Unsalted {algo} Hash Detected in Response",
                    "description": f"The response contains an unsalted {algo} hash of the value '{original}' ({h}). "
                                   f"Unsalted {algo} hashes are vulnerable to rainbow table attacks — "
                                   f"two identical passwords always produce the same hash.",
                    "url": self.target_url,
                    "recommendation": f"Replace {algo} with bcrypt, Argon2, or PBKDF2 with a unique salt per password.",
                    "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                })
                return

        for cookie_name, cookie_value in cookies.items():
            for h in md5_pattern.findall(cookie_value) + sha1_pattern.findall(cookie_value):
                if h.lower() in known_hashes:
                    algo, original = known_hashes[h.lower()]
                    print(f"Unsalted {algo} hash in cookie '{cookie_name}': {h}", flush=True)
                    self.add_vulnerability({
                        "vuln_type": "cryptographic_failure",
                        "severity": "critical",
                        "title": f"Unsalted {algo} Hash in Cookie '{cookie_name}'",
                        "description": f"Cookie '{cookie_name}' contains an unsalted {algo} hash of '{original}'. "
                                       f"This is vulnerable to rainbow table attacks.",
                        "url": self.target_url,
                        "recommendation": f"Replace {algo} with bcrypt, Argon2, or PBKDF2 with a unique salt per password.",
                        "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    })
                    return

        if found_md5:
            print(f"Found {len(found_md5)} potential MD5 hashes in response body", flush=True)
            self.add_vulnerability({
                "vuln_type": "cryptographic_failure",
                "severity": "medium",
                "title": "Potential MD5 Hashes Exposed in Response",
                "description": f"The response contains {len(found_md5)} value(s) matching MD5 hash pattern (32-char hex). "
                               f"MD5 is a weak hashing algorithm — if used for passwords, it is vulnerable to rainbow table attacks because it produces the same hash for the same input with no salt.",
                "url": self.target_url,
                "recommendation": "Use bcrypt, Argon2, or PBKDF2 with a unique salt for password hashing. Never use MD5 or SHA1.",
                "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
            })
        elif found_sha1:
            print(f"Found {len(found_sha1)} potential SHA1 hashes in response body", flush=True)
            self.add_vulnerability({
                "vuln_type": "cryptographic_failure",
                "severity": "medium",
                "title": "Potential SHA1 Hashes Exposed in Response",
                "description": f"The response contains {len(found_sha1)} value(s) matching SHA1 hash pattern (40-char hex). "
                               f"SHA1 is a weak hashing algorithm — identical inputs always produce identical hashes with no salt, making it vulnerable to rainbow table attacks.",
                "url": self.target_url,
                "recommendation": "Use bcrypt, Argon2, or PBKDF2 with a unique salt for password hashing. Never use SHA1.",
                "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
            })
