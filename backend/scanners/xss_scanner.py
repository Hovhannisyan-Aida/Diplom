from typing import List, Dict, Any
from scanners.base_scanner import BaseScanner
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
import logging

logger = logging.getLogger(__name__)

class XSSScanner(BaseScanner):

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "'><script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
    ]

    SKIP_EXTENSIONS = (
        '.css', '.js', '.png', '.jpg', '.jpeg',
        '.gif', '.ico', '.svg', '.woff', '.pdf',
        '.zip', '.mp4', '.mp3',
    )

    def scan(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting XSS scan for {self.target_url}")
        self._baselines = {}

        self._test_url_parameters(self.target_url)
        self._test_forms(self.target_url)

        subpages = self._collect_subpages(self.target_url)
        logger.info(f"Found {len(subpages)} subpages for XSS testing")
        for url in subpages:
            self._test_url_parameters(url)
            self._test_forms(url)

        logger.info(f"XSS scan finished, found {len(self.results)} vulnerabilities")
        return self.get_results()

    def _collect_subpages(self, url: str, max_pages: int = 5) -> list:
        response = self.make_request(url)
        if not response:
            return []
        base_domain = urlparse(url).netloc
        links = set()
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
        except Exception:
            return []
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            full = urljoin(url, href).split('#')[0]
            p = urlparse(full)
            if p.netloc != base_domain:
                continue
            if any(p.path.lower().endswith(ext) for ext in self.SKIP_EXTENSIONS):
                continue
            if full != url:
                links.add(full)
        return sorted(links)[:max_pages]

    def _get_baseline(self, url: str) -> str:
        if url not in self._baselines:
            resp = self.make_request(url)
            self._baselines[url] = resp.text if resp else ''
        return self._baselines[url]

    def _is_executable_reflection(self, response_text: str, payload: str) -> bool:
        """
        Check that the payload appears in the response unescaped (raw < > not &lt; &gt;)
        and outside of non-executing HTML contexts (comments, textarea, noscript).
        """
        if payload not in response_text:
            return False
        try:
            soup = BeautifulSoup(response_text, 'html.parser')
            for tag in soup.find_all(['textarea', 'noscript', 'template', 'xmp']):
                tag.decompose()
            for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
                comment.extract()
            return payload in str(soup)
        except Exception:
            return payload in response_text

    def _test_url_parameters(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        all_params = list(params.keys()) if params else ["q", "search", "query", "name", "id", "page"]

        baseline = self._get_baseline(url)

        for param in all_params:
            for payload in self.XSS_PAYLOADS:
                if params:
                    new_params = params.copy()
                    new_params[param] = [payload]
                    new_query = urlencode(new_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                else:
                    test_url = f"{url}?{param}={payload}"

                response = self.make_request(test_url)
                if not response:
                    continue

                ct = response.headers.get('Content-Type', '')
                if ct and 'text/html' not in ct:
                    continue

                if payload in baseline:
                    continue

                if self._is_executable_reflection(response.text, payload):
                    self.add_vulnerability({
                        "vuln_type": "xss",
                        "severity": "high",
                        "title": self.t(
                            f"Reflected XSS in parameter '{param}'",
                            f"Reflected XSS խոcелilутyan '{param}' parametrum",
                            f"Reflected XSS в параметре '{param}'"
                        ),
                        "description": self.t(
                            f"XSS payload was reflected unescaped in the HTML response via '{param}'.",
                            f"XSS payload-ը reflected e '{param}' parametri mjocov:",
                            f"XSS-нагрузка отразилась без экранирования через параметр '{param}'."
                        ),
                        "url": test_url,
                        "parameter": param,
                        "method": "GET",
                        "payload": payload,
                        "evidence": self.t(
                            f"Unescaped payload in HTML: {payload[:50]}",
                            f"Payload reflected e HTML-um: {payload[:50]}",
                            f"Нагрузка без экранирования в HTML: {payload[:50]}"
                        ),
                        "recommendation": self.t(
                            "Escape all user input before rendering in HTML. Implement a Content-Security-Policy header.",
                            "Escape arek bolor user inputs-y: Implement arek CSP headers.",
                            "Экранируйте все входные данные перед рендерингом. Внедрите заголовок Content-Security-Policy."
                        ),
                        "references": "https://owasp.org/www-community/attacks/xss/"
                    })
                    break

    def _test_forms(self, url: str):
        response = self.make_request(url)
        if not response:
            return

        baseline = self._get_baseline(url)

        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        logger.info(f"Found {len(forms)} forms for XSS testing on {url}")

        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(url, action) if action else url

            inputs = form.find_all(['input', 'textarea'])
            form_data = {}
            for inp in inputs:
                name = inp.get('name')
                if name:
                    form_data[name] = inp.get('value', 'test')

            if not form_data:
                continue

            for field in form_data:
                for payload in self.XSS_PAYLOADS:
                    test_data = form_data.copy()
                    test_data[field] = payload

                    if method == 'post':
                        resp = self.make_request(form_url, method='POST', data=test_data)
                    else:
                        resp = self.make_request(form_url, method='GET', params=test_data)

                    if not resp:
                        continue

                    ct = resp.headers.get('Content-Type', '')
                    if ct and 'text/html' not in ct:
                        continue

                    if payload in baseline:
                        continue

                    if self._is_executable_reflection(resp.text, payload):
                        self.add_vulnerability({
                            "vuln_type": "xss",
                            "severity": "high",
                            "title": self.t(
                                f"Reflected XSS in form field '{field}'",
                                f"Reflected XSS form-i '{field}' dastum",
                                f"Reflected XSS в поле формы '{field}'"
                            ),
                            "description": self.t(
                                f"XSS payload reflected unescaped via form field '{field}' ({method.upper()}).",
                                f"XSS payload reflected e form-i '{field}' dasti mjocov ({method.upper()}).",
                                f"XSS-нагрузка отразилась без экранирования через поле '{field}' ({method.upper()})."
                            ),
                            "url": form_url,
                            "parameter": field,
                            "method": method.upper(),
                            "payload": payload,
                            "evidence": self.t(
                                "Unescaped payload found in HTML response",
                                "Payload reflected e HTML response-um",
                                "Нагрузка без экранирования найдена в HTML-ответе"
                            ),
                            "recommendation": self.t(
                                "Escape all user input before rendering in HTML. Implement a Content-Security-Policy header.",
                                "Escape arek bolor user inputs-y. Implement arek CSP headers.",
                                "Экранируйте все входные данные перед рендерингом. Внедрите заголовок Content-Security-Policy."
                            ),
                            "references": "https://owasp.org/www-community/attacks/xss/"
                        })
                        break
