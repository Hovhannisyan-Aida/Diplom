import re
import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from scanners.base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class CSRFScanner(BaseScanner):
    """
    CSRF (Cross-Site Request Forgery) Scanner
    Checks for missing or weak CSRF protections on web forms and cookies.
    Bilingual: EN / HY
    """

    CSRF_TOKEN_NAMES = [
        'csrf', 'csrf_token', 'csrftoken', 'csrfmiddlewaretoken',
        '_token', 'authenticity_token', '__requestverificationtoken',
        'xsrf', 'xsrf_token', '_csrf', '_csrf_token', 'anti_csrf',
        'nonce', 'form_token', 'security_token',
    ]

    SKIP_EXTENSIONS = (
        '.css', '.js', '.png', '.jpg', '.jpeg',
        '.gif', '.ico', '.svg', '.woff', '.pdf',
        '.zip', '.mp4', '.mp3',
    )

    def __init__(self, target_url: str, language: str = 'en'):
        super().__init__(target_url, language)
        self._scanned_urls = set()

    # ------------------------------------------------------------------ #
    #  Main entry point                                                    #
    # ------------------------------------------------------------------ #

    def scan(self):
        logger.info(f"Starting CSRF scan for {self.target_url}")

        # Step 1 — load main page
        response = self.make_request(self.target_url)
        if response is None:
            logger.warning(f"No response from {self.target_url}")
            return self.vulnerabilities

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
        except Exception as e:
            logger.error(f"Failed to parse HTML: {e}")
            return self.vulnerabilities

        # Step 2 — cookies and headers checked once from main page
        self._check_cookies(response)
        self._check_csrf_headers(response)

        # Step 3 — check forms on main page
        self._check_forms(soup, self.target_url)
        self._scanned_urls.add(self.target_url)

        # Step 4 — collect subpage links and scan each for forms
        subpages = self._collect_links(soup)
        logger.info(f"Found {len(subpages)} subpages to scan for forms")

        for page_url in subpages:
            if page_url in self._scanned_urls:
                continue

            self._scanned_urls.add(page_url)
            logger.info(f"Scanning subpage: {page_url}")

            page_response = self.make_request(page_url)
            if page_response is None:
                continue

            try:
                page_soup = BeautifulSoup(page_response.text, 'html.parser')
            except Exception:
                continue

            self._check_forms(page_soup, page_url)

        logger.info(f"CSRF scan finished, found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities

    # ------------------------------------------------------------------ #
    #  Link collector                                                      #
    # ------------------------------------------------------------------ #

    def _collect_links(self, soup, max_pages: int = 10):
        """
        Find all internal links on the page.
        Returns up to max_pages absolute URLs on the same domain.
        """
        base_domain = urlparse(self.target_url).netloc
        links = set()

        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href'].strip()

            # Skip anchors, javascript, mailto, tel
            if href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue

            full_url = urljoin(self.target_url, href)
            parsed = urlparse(full_url)

            # Same domain only
            if parsed.netloc != base_domain:
                continue

            # Skip static files
            if any(parsed.path.lower().endswith(ext) for ext in self.SKIP_EXTENSIONS):
                continue

            # Remove URL fragment
            clean_url = full_url.split('#')[0]
            if clean_url and clean_url != self.target_url:
                links.add(clean_url)

        return sorted(links)[:max_pages]

    # ------------------------------------------------------------------ #
    #  Check 1 — Forms without CSRF tokens                                #
    # ------------------------------------------------------------------ #

    def _check_forms(self, soup, page_url: str):
        """Check all POST forms on a given page for missing CSRF tokens."""
        forms = soup.find_all('form')

        if not forms:
            logger.info(f"No forms found on {page_url}")
            return

        for form in forms:
            method = form.get('method', 'get').lower()
            action = form.get('action', page_url)

            if method != 'post':
                continue

            inputs = form.find_all('input')
            has_csrf_token = False
            token_value = None

            for inp in inputs:
                field_name = (inp.get('name') or '').lower()
                field_type = (inp.get('type') or '').lower()

                if field_name in self.CSRF_TOKEN_NAMES:
                    has_csrf_token = True
                    token_value = inp.get('value', '')
                    break

                if field_type == 'hidden' and any(
                    kw in field_name for kw in ['csrf', 'xsrf', 'nonce', 'antiforgery']
                ):
                    has_csrf_token = True
                    token_value = inp.get('value', '')
                    break

            if not has_csrf_token:
                self.add_vulnerability({
                    'vuln_type': 'csrf',
                    'title': self.t(
                        'Missing CSRF Token in Form',
                        'Ձևաթղթում CSRF Token բացակայում է'
                    ),
                    'severity': 'high',
                    'description': self.t(
                        f'A POST form (action: "{action}") was found on "{page_url}" '
                        f'without a CSRF token. '
                        f'This allows attackers to forge requests on behalf of authenticated users.',
                        f'POST ձևաթուղթ (action: "{action}") հայտնաբերվել է "{page_url}" էջում '
                        f'առանց CSRF token-ի։ '
                        f'Սա թույլ է տալիս հարձակվողներին կեղծ հարցումներ կատարել '
                        f'վավերացված օգտատիրոջ անունից։'
                    ),
                    'recommendation': self.t(
                        'Add a hidden CSRF token field to all POST forms. '
                        'Use a cryptographically random token (>=32 characters) '
                        'tied to the user session.',
                        'Добавьте скрытое поле CSRF-токена во все POST-формы. '
                        'Используйте криптографически случайный токен (>=32 символов), '
                        'привязанный к сессии пользователя.',
                        'Ավելացրեք թաքնված CSRF token դաշտ բոլոր POST ձևաթղթերում։ '
                        'Օգտագործեք կրիպտոգրաֆիկ պատահական token (>=32 նիշ) '
                        'կապված օգտատիրոջ session-ի հետ։'
                    ),
                    'url': page_url,
                })

            elif token_value is not None:
                self._check_token_strength(token_value, action, page_url)

    # ------------------------------------------------------------------ #
    #  Check 2 — Token strength                                           #
    # ------------------------------------------------------------------ #

    def _check_token_strength(self, token_value: str, action: str, page_url: str):
        """Check if an existing CSRF token is strong enough."""

        if len(token_value) < 32:
            self.add_vulnerability({
                'vuln_type': 'csrf',
                'title': self.t(
                    'Weak CSRF Token — Too Short',
                    'Թույլ CSRF Token — Շատ Կարճ'
                ),
                'severity': 'medium',
                'description': self.t(
                    f'The CSRF token in form (action: "{action}") on "{page_url}" '
                    f'is only {len(token_value)} characters long. '
                    f'Tokens shorter than 32 characters can be brute-forced.',
                    f'CSRF token-ը ձևաթղթում (action: "{action}") "{page_url}" էջում '
                    f'ունի ընդամենը {len(token_value)} նիշ։ '
                    f'32 նիշից կարճ token-ները կարող են brute-force-ով կոտրվել։'
                ),
                'recommendation': self.t(
                    'Use a cryptographically secure random token of at least 32 characters.',
                'Используйте криптографически стойкий случайный токен длиной не менее 32 символов.',
                    'Օգտագործեք կրիպտոգրաֆիկ անվտանգ պատահական token '
                    'առնվազն 32 նիշ երկարությամբ։'
                ),
                'url': page_url,
            })
            return

        predictable_patterns = [
            r'^0+$',
            r'^1234',
            r'^abcd',
            r'^(.)\1{6,}$',
        ]

        for pattern in predictable_patterns:
            if re.match(pattern, token_value, re.IGNORECASE):
                self.add_vulnerability({
                    'vuln_type': 'csrf',
                    'title': self.t(
                        'Weak CSRF Token — Predictable Value',
                        'Թույլ CSRF Token — Կանխատեսելի Արժեք'
                    ),
                    'severity': 'medium',
                    'description': self.t(
                        f'The CSRF token "{token_value[:12]}..." on "{page_url}" '
                        f'follows a predictable pattern. '
                        f'Predictable tokens can be guessed by attackers.',
                        f'CSRF token-ը "{token_value[:12]}..." "{page_url}" էջում '
                        f'հետևում է կանխատեսելի ձևի։ '
                        f'Կանխատեսելի token-ները կարող են գուշակվել հարձակվողների կողմից։'
                    ),
                    'recommendation': self.t(
                        'Use secrets.token_hex(32) or os.urandom(32) to generate CSRF tokens.',
                'Используйте secrets.token_hex(32) или os.urandom(32) для генерации CSRF-токенов.',
                        'Օգտագործեք secrets.token_hex(32) կամ os.urandom(32) '
                        'CSRF token-ներ ստեղծելու համար։'
                    ),
                    'url': page_url,
                })
                return

    # ------------------------------------------------------------------ #
    #  Check 3 — Cookie SameSite attribute                                #
    # ------------------------------------------------------------------ #

    def _check_cookies(self, response):
        """Check cookies for missing SameSite and Secure attributes."""

        set_cookie_headers = []
        try:
            set_cookie_headers = response.raw.headers.getlist('Set-Cookie')
        except Exception:
            single = response.headers.get('Set-Cookie', '')
            if single:
                set_cookie_headers = [single]

        if not set_cookie_headers:
            return

        for cookie_str in set_cookie_headers:
            cookie_lower = cookie_str.lower()
            cookie_name = cookie_str.split('=')[0].strip()

            if 'samesite' not in cookie_lower:
                self.add_vulnerability({
                    'vuln_type': 'csrf',
                    'title': self.t(
                        'Cookie Missing SameSite Attribute',
                        'Cookie-ին բացակայում է SameSite Attribute'
                    ),
                    'severity': 'medium',
                    'description': self.t(
                        f'Cookie "{cookie_name}" does not have a SameSite attribute. '
                        f'Without SameSite, the cookie is sent with cross-site requests, '
                        f'enabling CSRF attacks.',
                        f'Cookie "{cookie_name}"-ը չունի SameSite attribute։ '
                        f'Առանց SameSite-ի, cookie-ն ուղարկվում է cross-site հարցումների հետ, '
                        f'ինչը հնարավոր է դարձնում CSRF հարձակումները։'
                    ),
                    'recommendation': self.t(
                        'Add SameSite=Strict or SameSite=Lax to all session cookies.',
                    'Добавьте SameSite=Strict или SameSite=Lax ко всем сессионным cookie.',
                        'Ավելացրեք SameSite=Strict կամ SameSite=Lax '
                        'բոլոր session cookie-ներին։'
                    ),
                    'url': self.target_url,
                })

            elif 'samesite=none' in cookie_lower and 'secure' not in cookie_lower:
                self.add_vulnerability({
                    'vuln_type': 'csrf',
                    'title': self.t(
                        'Cookie SameSite=None Without Secure Flag',
                        'Cookie SameSite=None-ը առանց Secure Flag-ի'
                    ),
                    'severity': 'medium',
                    'description': self.t(
                        f'Cookie "{cookie_name}" has SameSite=None but is missing the Secure flag. '
                        f'Browsers reject SameSite=None cookies without Secure.',
                        f'Cookie "{cookie_name}"-ն ունի SameSite=None, '
                        f'բայց բացակայում է Secure flag-ը։ '
                        f'Դիտարկիչները մերժում են SameSite=None cookie-ները '
                        f'առանց Secure-ի։'
                    ),
                    'recommendation': self.t(
                        'Add the Secure flag to all SameSite=None cookies.',
                    'Добавьте флаг Secure ко всем cookie с SameSite=None.',
                        'Ավելացրեք Secure flag բոլոր SameSite=None cookie-ներին։'
                    ),
                    'url': self.target_url,
                })

    # ------------------------------------------------------------------ #
    #  Check 4 — CSRF-related response headers                            #
    # ------------------------------------------------------------------ #

    def _check_csrf_headers(self, response):
        """Check for CSRF-protective response headers."""

        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        if 'x-frame-options' not in headers_lower:
            self.add_vulnerability({
                'vuln_type': 'csrf',
                'title': self.t(
                    'Missing X-Frame-Options Header',
                    'Բացակայում է X-Frame-Options Header'
                ),
                'severity': 'medium',
                'description': self.t(
                    'The X-Frame-Options header is missing. Without it, the page can be '
                    'embedded in an iframe on a malicious site, enabling clickjacking '
                    'attacks (CSRF via UI redressing).',
                    'X-Frame-Options header-ը բացակայում է։ Առանց դրա, էջը կարող է '
                    'ներառվել iframe-ում վնասաբեր կայքում, հնարավոր դարձնելով '
                    'clickjacking հարձակումները։'
                ),
                'recommendation': self.t(
                    'Add X-Frame-Options: DENY or SAMEORIGIN header.',
                'Добавьте заголовок X-Frame-Options: DENY или SAMEORIGIN.',
                    'Ավելացրեք X-Frame-Options: DENY կամ SAMEORIGIN header։'
                ),
                'url': self.target_url,
            })

        cors_origin = headers_lower.get('access-control-allow-origin', '')

        if cors_origin == '*':
            self.add_vulnerability({
                'vuln_type': 'csrf',
                'title': self.t(
                    'Wildcard CORS Policy — CSRF Risk',
                    'Wildcard CORS Քաղաքականություն — CSRF Ռիսկ'
                ),
                'severity': 'high',
                'description': self.t(
                    'The server returns Access-Control-Allow-Origin: * which allows any '
                    'website to make cross-origin requests. Combined with missing CSRF '
                    'tokens, this significantly increases CSRF attack risk.',
                    'Սերվերը վերադարձնում է Access-Control-Allow-Origin: * '
                    'ինչը թույլ է տալիս ցանկացած կայքի cross-origin հարցումներ կատարել։ '
                    'CSRF token-ների բացակայության հետ զուգորդված՝ '
                    'սա զգալիորեն մեծացնում է CSRF հարձակման ռիսկը։'
                ),
                'recommendation': self.t(
                    'Restrict Access-Control-Allow-Origin to specific trusted domains. '
                    'Never use wildcard (*) for authenticated endpoints.',
                    'Ограничьте Access-Control-Allow-Origin конкретными доверенными доменами. '
                    'Никогда не используйте wildcard (*) для аутентифицированных эндпоинтов.',
                    'Սահմանափակեք Access-Control-Allow-Origin-ը վստահելի դոմեններով։ '
                    'Երբեք մի օգտագործեք wildcard (*) վավերացված endpoint-ների համար։'
                ),
                'url': self.target_url,
            })