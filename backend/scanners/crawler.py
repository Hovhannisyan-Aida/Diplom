import requests
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)

SKIP_EXTENSIONS = (
    '.css', '.js', '.png', '.jpg', '.jpeg',
    '.gif', '.ico', '.svg', '.woff', '.pdf',
    '.zip', '.mp4', '.mp3',
)


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

            soup = BeautifulSoup(response.text, 'html.parser')

            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href'].strip()

                if href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    continue

                full_url = urljoin(url, href).split('#')[0]
                parsed = urlparse(full_url)

                if parsed.netloc != self.base_domain:
                    continue

                if any(parsed.path.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
                    continue

                if full_url not in self.visited:
                    self._crawl_page(full_url)

        except Exception as e:
            logger.warning(f"Error crawling {url}: {str(e)}")
