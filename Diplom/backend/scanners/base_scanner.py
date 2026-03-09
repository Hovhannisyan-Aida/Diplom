import requests
from typing import List, Dict, Any
from urllib.parse import urlparse
import logging
import urllib3

# SSL warnings-ը անջատել
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class BaseScanner:
    """Հիմնական scanner class"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc
        self.results = []
    
    def make_request(self, url: str, method: str = "GET", **kwargs) -> requests.Response:
        """HTTP հարցում"""
        try:
            # SSL verification-ը անջատել (միայն testing-ի համար)
            response = requests.request(method, url, timeout=10, verify=False, **kwargs)
            return response
        except requests.RequestException as e:
            logger.error(f"Request failed for {url}: {str(e)}")
            return None
    
    def add_vulnerability(self, vuln: Dict[str, Any]):
        """Խոցելիություն ավելացնել"""
        self.results.append(vuln)
    
    def get_results(self) -> List[Dict[str, Any]]:
        """Արդյունքներ վերադարձնել"""
        return self.results