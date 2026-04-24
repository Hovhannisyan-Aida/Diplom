from typing import List, Dict, Any
from scanners.base_scanner import BaseScanner
import ssl
import socket
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone
import hashlib
import re
import logging

logger = logging.getLogger(__name__)

class CryptoScanner(BaseScanner):

    def scan(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting Crypto scan for {self.target_url}")

        parsed_url = urlparse(self.target_url)
        hostname = parsed_url.hostname
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)

        if parsed_url.scheme != 'https':
            self.add_vulnerability({
                "vuln_type": "cryptographic_failure",
                "severity": "high",
                "title": self.t(
                    "HTTP Used Instead of HTTPS",
                    "Օգտագործվում է HTTP HTTPS-ի փոխարեն"
                ),
                "description": self.t(
                    f"The website {self.target_url} is not using HTTPS. All data transmitted is unencrypted and vulnerable to interception.",
                    f"{self.target_url} կայքը չի օգտագործում HTTPS։ Բոլոր փոխանցված տվյալները չգաղտնագրված են և խոցելի են գաղտնալսման համար։"
                ),
                "url": self.target_url,
                "recommendation": self.t(
                    "Enable HTTPS with a valid SSL/TLS certificate. Redirect all HTTP traffic to HTTPS.",
                    "Ակտիվացրեք HTTPS-ը վավեր SSL/TLS սերտիֆիկատով։ Վերահղեք բոլոր HTTP տրաֆիկը HTTPS-ի։",
                    "Включите HTTPS с действительным сертификатом SSL/TLS. Перенаправьте весь HTTP-трафик на HTTPS."
                ),
                "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
            })

            response = self.make_request(self.target_url, allow_redirects=False)
            if response:
                location = response.headers.get("location", "")
                if response.status_code in (301, 302) and location.startswith("https://"):
                    logger.info(f"HTTP redirects to HTTPS at {location}")
                else:
                    self.add_vulnerability({
                        "vuln_type": "cryptographic_failure",
                        "severity": "medium",
                        "title": self.t(
                            "No HTTP to HTTPS Redirect",
                            "HTTP-ից HTTPS վերահղում չկա"
                        ),
                        "description": self.t(
                            "The server does not redirect HTTP traffic to HTTPS, allowing users to browse insecurely.",
                            "Սերվերը HTTP տրաֆիկը HTTPS-ի չի վերահղում, ինչը թույլ է տալիս օգտատերերին անապահով կերպով դիտել կայքը։"
                        ),
                        "url": self.target_url,
                        "recommendation": self.t(
                            "Configure the server to redirect all HTTP requests to HTTPS (301 redirect).",
                            "Կարգավորեք սերվերը բոլոր HTTP հարցումները HTTPS-ի վերահղելու համար (301 redirect)։",
                    "Настройте сервер для перенаправления всех HTTP-запросов на HTTPS (301 redirect)."
                        ),
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

                        logger.info(f"TLS version: {version}, cipher: {cipher}")

                        if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                            self.add_vulnerability({
                                "vuln_type": "cryptographic_failure",
                                "severity": "high",
                                "title": self.t(
                                    f"Weak TLS Version: {version}",
                                    f"Թույլ TLS տարբերակ՝ {version}"
                                ),
                                "description": self.t(
                                    f"The server supports outdated TLS version {version}, which has known vulnerabilities.",
                                    f"Սերվերն աջակցում է հնացած TLS {version} տարբերակին, որն ունի հայտնի խոցելիություններ։"
                                ),
                                "url": self.target_url,
                                "recommendation": self.t(
                                    "Disable TLS 1.0, TLS 1.1, and all SSL versions. Use TLS 1.2 or TLS 1.3 only.",
                                    "Անջատեք TLS 1.0, TLS 1.1 և բոլոր SSL տարբերակները։ Օգտագործեք միայն TLS 1.2 կամ TLS 1.3։",
                        "Отключите TLS 1.0, TLS 1.1 и все версии SSL. Используйте только TLS 1.2 или TLS 1.3."
                                ),
                                "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                            })

                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
                        if cipher and any(weak in str(cipher) for weak in weak_ciphers):
                            self.add_vulnerability({
                                "vuln_type": "cryptographic_failure",
                                "severity": "medium",
                                "title": self.t(
                                    "Weak Cipher Suite",
                                    "Թույլ Cipher Suite"
                                ),
                                "description": self.t(
                                    f"The server supports weak cipher suite: {cipher[0]}",
                                    f"Սերվերն աջակցում է թույլ cipher suite-ին՝ {cipher[0]}"
                                ),
                                "url": self.target_url,
                                "recommendation": self.t(
                                    "Disable weak cipher suites. Use strong ciphers like AES-GCM.",
                                    "Անջատեք թույլ cipher suite-ները։ Օգտագործեք ուժեղ cipher-ներ, ինչպիսիք են AES-GCM-ը։",
                        "Отключите слабые наборы шифров. Используйте надёжные алгоритмы, например AES-GCM."
                                ),
                                "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                            })

                        if cert:
                            expire_str = cert.get("notAfter", "")
                            if expire_str:
                                try:
                                    expire_date = datetime.strptime(expire_str.rsplit(' ', 1)[0], "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                                    days_left = (expire_date - datetime.now(timezone.utc)).days
                                    logger.info(f"Certificate expires in {days_left} days")
                                    if days_left < 0:
                                        self.add_vulnerability({
                                            "vuln_type": "cryptographic_failure",
                                            "severity": "critical",
                                            "title": self.t(
                                                "SSL Certificate Expired",
                                                "SSL Սերտիֆիկատի Ժամկետը Լրացել Է"
                                            ),
                                            "description": self.t(
                                                f"The SSL certificate expired {abs(days_left)} days ago on {expire_date.strftime('%Y-%m-%d')}.",
                                                f"SSL սերտիֆիկատի ժամկետը լրացել է {abs(days_left)} օր առաջ՝ {expire_date.strftime('%Y-%m-%d')}-ին։"
                                            ),
                                            "url": self.target_url,
                                            "recommendation": self.t(
                                                "Renew the SSL certificate immediately.",
                                                "Անհապաղ թարմացրեք SSL սերտիֆիկատը։",
                                "Немедленно обновите SSL-сертификат."
                                            ),
                                            "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                                        })
                                    elif days_left < 30:
                                        self.add_vulnerability({
                                            "vuln_type": "cryptographic_failure",
                                            "severity": "medium",
                                            "title": self.t(
                                                "SSL Certificate Expiring Soon",
                                                "SSL Սերտիֆիկատի Ժամկետը Շուտ Կլրանա"
                                            ),
                                            "description": self.t(
                                                f"The SSL certificate expires in {days_left} days on {expire_date.strftime('%Y-%m-%d')}.",
                                                f"SSL սերտիֆիկատի ժամկետը կլրանա {days_left} օրից՝ {expire_date.strftime('%Y-%m-%d')}-ին։"
                                            ),
                                            "url": self.target_url,
                                            "recommendation": self.t(
                                                "Renew the SSL certificate before it expires.",
                                                "Թարմացրեք SSL սերտիֆիկատը մինչ ժամկետի լրանալը։",
                                "Обновите SSL-сертификат до истечения срока действия."
                                            ),
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
                        "title": self.t(
                            "Self-Signed SSL Certificate",
                            "Ինքնստորագրված SSL Սերտիֆիկատ"
                        ),
                        "description": self.t(
                            "The server is using a self-signed certificate which is not trusted by browsers and vulnerable to MITM attacks.",
                            "Սերվերն օգտագործում է ինքնստորագրված սերտիֆիկատ, որը վստահելի չէ բրաուզերների համար և խոցելի է MITM հարձակումների նկատմամբ։"
                        ),
                        "url": self.target_url,
                        "recommendation": self.t(
                            "Replace the self-signed certificate with one from a trusted Certificate Authority (e.g. Let's Encrypt).",
                            "Փոխարինեք ինքնստորագրված սերտիֆիկատը վստահված Certificate Authority-ի (օրինակ՝ Let's Encrypt) սերտիֆիկատով։",
                    "Замените самоподписанный сертификат на сертификат от доверенного центра сертификации (например, Let's Encrypt)."
                        ),
                        "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    })
                else:
                    self.add_vulnerability({
                        "vuln_type": "cryptographic_failure",
                        "severity": "critical",
                        "title": self.t(
                            "SSL/TLS Certificate Error",
                            "SSL/TLS Սերտիֆիկատի Սխալ"
                        ),
                        "description": self.t(
                            f"SSL/TLS certificate validation failed: {str(e)}",
                            f"SSL/TLS սերտիֆիկատի ստուգումն ձախողվեց՝ {str(e)}"
                        ),
                        "url": self.target_url,
                        "recommendation": self.t(
                            "Install a valid SSL/TLS certificate from a trusted Certificate Authority.",
                            "Տեղադրեք վավեր SSL/TLS սերտիֆիկատ վստահված Certificate Authority-ից։",
                    "Установите действительный SSL/TLS-сертификат от доверенного центра сертификации."
                        ),
                        "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    })
            except ssl.SSLError as e:
                self.add_vulnerability({
                    "vuln_type": "cryptographic_failure",
                    "severity": "critical",
                    "title": self.t(
                        "SSL/TLS Error",
                        "SSL/TLS Սխալ"
                    ),
                    "description": self.t(
                        f"SSL/TLS error: {str(e)}",
                        f"SSL/TLS սխալ՝ {str(e)}"
                    ),
                    "url": self.target_url,
                    "recommendation": self.t(
                        "Review and fix the SSL/TLS configuration.",
                        "Ստուգեք և շտկեք SSL/TLS կարգավորումները։",
                    "Проверьте и исправьте конфигурацию SSL/TLS."
                    ),
                    "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                })
            except socket.timeout:
                logger.warning(f"Timeout connecting to {hostname}:{port}")
                self.add_vulnerability({
                    "vuln_type": "cryptographic_failure",
                    "severity": "medium",
                    "title": self.t(
                        "SSL/TLS Check Timed Out",
                        "SSL/TLS Ստուգումը Ժամկետանց Եղավ"
                    ),
                    "description": self.t(
                        f"Could not complete SSL/TLS analysis for {hostname}:{port} — connection timed out after 10 seconds. Certificate validity, TLS version, and cipher suite could not be verified.",
                        f"Հնարավոր չեղավ կատարել SSL/TLS վերլուծություն {hostname}:{port}-ի համար — կապը ժամկետանց եղավ 10 վայրկյանից հետո։ Չհաջողվեց ստուգել սերտիֆիկատի վավերականությունը, TLS տարբերակը և cipher suite-ը։"
                    ),
                    "url": self.target_url,
                    "recommendation": self.t(
                        "Ensure port 443 is reachable and the server responds to SSL/TLS handshakes promptly.",
                        "Համոզվեք, որ 443 պորտը հասանելի է և սերվերը արագ արձագանքում է SSL/TLS handshake-ներին։",
                    "Убедитесь, что порт 443 доступен и сервер своевременно отвечает на SSL/TLS-рукопожатия."
                    ),
                    "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                })
            except Exception as e:
                logger.error(f"Crypto scan error: {str(e)}")

        https_response = None
        if parsed_url.scheme == 'https':
            https_response = self.make_request(self.target_url)
            if https_response:
                hsts = https_response.headers.get("strict-transport-security", "")
                if not hsts:
                    self.add_vulnerability({
                        "vuln_type": "cryptographic_failure",
                        "severity": "medium",
                        "title": self.t(
                            "Missing HSTS Header",
                            "Բացակայում է HSTS Header"
                        ),
                        "description": self.t(
                            "HTTP Strict Transport Security (HSTS) header is not set. This allows potential downgrade attacks.",
                            "HTTP Strict Transport Security (HSTS) header-ը սահմանված չէ։ Սա թույլ է տալիս հնարավոր downgrade հարձակումներ։"
                        ),
                        "url": self.target_url,
                        "recommendation": self.t(
                            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
                            "Ավելացրեք Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    "Добавьте Strict-Transport-Security: max-age=31536000; includeSubDomains"
                        ),
                        "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    })
                    logger.info(f"HSTS header missing on {self.target_url}")
                else:
                    logger.info(f"HSTS header present: {hsts}")

        self._check_weak_hashing(response=https_response)

        logger.info(f"Crypto scan finished, found {len(self.results)} vulnerabilities")
        return self.get_results()

    def _check_weak_hashing(self, response=None):
        md5_pattern = re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE)
        sha1_pattern = re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE)

        known_values = ["admin", "password", "123456", "test", "user", "guest"]
        known_hashes = {}
        for val in known_values:
            known_hashes[hashlib.md5(val.encode()).hexdigest()] = ("MD5", val)
            known_hashes[hashlib.sha1(val.encode()).hexdigest()] = ("SHA1", val)

        parsed = urlparse(self.target_url)
        url_params = parse_qs(parsed.query)
        for param, values in url_params.items():
            for val in values:
                is_md5 = md5_pattern.fullmatch(val.strip())
                is_sha1 = sha1_pattern.fullmatch(val.strip())
                if is_md5 or is_sha1:
                    algo = "MD5" if is_md5 else "SHA1"
                    known = known_hashes.get(val.strip().lower())
                    if not known:
                        continue
                    desc_en = (
                        f"URL parameter '{param}' contains an unsalted {algo} hash of the value '{known[1]}' ({val}). "
                        f"{algo} produces the same hash for the same input with no salt, making it vulnerable to rainbow table attacks."
                    )
                    desc_hy = (
                        f"URL parametr '{param}'-ը պարունակում է '{known[1]}' ({val}) արժեքի unsalted {algo} hash։ "
                        f"{algo}-ն նույն input-ի համար միշտ տալիս է նույն hash-ը առանց salt-ի, ինչն այն խոցելի է rainbow table հարձակումների նկատմամբ։"
                    )
                    logger.info(f"Known hash in URL param '{param}': {val} ({algo})")
                    self.add_vulnerability({
                        "vuln_type": "cryptographic_failure",
                        "severity": "critical",
                        "title": self.t(
                            f"Weak Unsalted {algo} Hash in URL Parameter '{param}'",
                            f"Թույլ Unsalted {algo} Hash URL Պարամետրում '{param}'"
                        ),
                        "description": self.t(desc_en, desc_hy),
                        "url": self.target_url,
                        "recommendation": self.t(
                            f"Never use {algo} for passwords. Use bcrypt, Argon2, or PBKDF2 with a unique salt.",
                            f"Երբեք մի օգտագործեք {algo}-ն գաղտնաբառերի համար։ Օգտագործեք bcrypt, Argon2 կամ PBKDF2 եզակի salt-ով։"
                        ),
                        "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    })

        if response is None:
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
                logger.info(f"Unsalted {algo} hash found in response: {h} = '{original}'")
                self.add_vulnerability({
                    "vuln_type": "cryptographic_failure",
                    "severity": "critical",
                    "title": self.t(
                        f"Unsalted {algo} Hash Detected in Response",
                        f"Unsalted {algo} Hash Haytnabervel E Response-um"
                    ),
                    "description": self.t(
                        f"The response contains an unsalted {algo} hash of the value '{original}' ({h}). "
                        f"Unsalted {algo} hashes are vulnerable to rainbow table attacks — "
                        f"two identical passwords always produce the same hash.",
                        f"Response-y parunakum e '{original}' ({h}) arjeqi unsalted {algo} hash։ "
                        f"Unsalted {algo} hash-ery khoceli en rainbow table hardzakumneri nkatmamb — "
                        f"erku nuyn gaghtnabarn misht talis en nuyn hash-y։"
                    ),
                    "url": self.target_url,
                    "recommendation": self.t(
                        f"Replace {algo} with bcrypt, Argon2, or PBKDF2 with a unique salt per password.",
                        f"Poxarinekh {algo}-n bcrypt-ov, Argon2-ov kam PBKDF2-ov yuraqanchyur gaghtnabari hamar ezaki salt-ov։"
                    ),
                    "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                })

        for cookie_name, cookie_value in cookies.items():
            for h in md5_pattern.findall(cookie_value) + sha1_pattern.findall(cookie_value):
                if h.lower() in known_hashes:
                    algo, original = known_hashes[h.lower()]
                    logger.info(f"Unsalted {algo} hash in cookie '{cookie_name}': {h}")
                    self.add_vulnerability({
                        "vuln_type": "cryptographic_failure",
                        "severity": "critical",
                        "title": self.t(
                            f"Unsalted {algo} Hash in Cookie '{cookie_name}'",
                            f"Unsalted {algo} Hash '{cookie_name}' Cookie-um"
                        ),
                        "description": self.t(
                            f"Cookie '{cookie_name}' contains an unsalted {algo} hash of '{original}'. "
                            f"This is vulnerable to rainbow table attacks.",
                            f"'{cookie_name}' cookie-n parunakum e '{original}'-i unsalted {algo} hash։ "
                            f"Sa khoceli e rainbow table hardzakumneri nkatmamb։"
                        ),
                        "url": self.target_url,
                        "recommendation": self.t(
                            f"Replace {algo} with bcrypt, Argon2, or PBKDF2 with a unique salt per password.",
                            f"Poxarinekh {algo}-n bcrypt-ov, Argon2-ov kam PBKDF2-ov yuraqanchyur gaghtnabari hamar ezaki salt-ov։"
                        ),
                        "references": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    })

        if found_md5:
            logger.info(f"Found {len(found_md5)} potential MD5 hashes in response body (no known match)")
        if found_sha1:
            logger.info(f"Found {len(found_sha1)} potential SHA1 hashes in response body (no known match)")
