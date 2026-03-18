import requests
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set
import logging

logger = logging.getLogger(__name__)

class WebCrawler:

    def __init__(self, base_url: str, max_pages: int = 10):
        self.base_url = base_url
        self.max_pages = max_pages
        self.visited = set()
        self.urls_with_params = set()
        self.base_domain = urlparse(base_url).netloc

    def crawl(self) -> Set[str]:
        logger.info(f"Starting crawl of {self.base_url}")

        try:
            self._crawl_page(self.base_url)
        except Exception as e:
            logger.warning(f"Crawl failed: {str(e)}")

        logger.info(f"Crawl complete. Found {len(self.urls_with_params)} URLs with parameters")
        return self.urls_with_params

    def _crawl_page(self, url: str):
        if len(self.visited) >= self.max_pages:
            return

        if url in self.visited:
            return

        parsed_url = urlparse(url)
        if parsed_url.netloc != self.base_domain:
            return

        self.visited.add(url)

        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if response.status_code != 200:
                return

            if parse_qs(parsed_url.query):
                self.urls_with_params.add(url)

            if 'text/html' not in response.headers.get('Content-Type', ''):
                return

        except Exception as e:
            logger.warning(f"Error crawling {url}: {str(e)}")
