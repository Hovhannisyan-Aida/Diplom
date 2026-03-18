import requests
from typing import List, Dict, Any
from urllib.parse import urlparse
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class BaseScanner:

    def __init__(self, target_url: str, language: str = 'en'):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc
        self.results = []
        self.vulnerabilities = []
        self.language = language

    def t(self, en: str, hy: str) -> str:
        return hy if self.language == 'hy' else en

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    def make_request(self, url: str, method: str = "GET", **kwargs) -> requests.Response:
        try:
            headers = kwargs.pop("headers", {})
            merged_headers = {**self.HEADERS, **headers}
            response = requests.request(method, url, timeout=10, verify=False, headers=merged_headers, **kwargs)
            return response
        except requests.RequestException as e:
            logger.error(f"Request failed for {url}: {str(e)}")
            return None

    def add_vulnerability(self, vuln: Dict[str, Any]):
        self.results.append(vuln)
        self.vulnerabilities.append(vuln)

    def get_results(self) -> List[Dict[str, Any]]:
        return self.results
