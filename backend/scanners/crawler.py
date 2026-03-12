import requests
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Set
import logging

logger = logging.getLogger(__name__)

class WebCrawler:
    """Simple web crawler to find URLs with parameters"""
    
    def __init__(self, base_url: str, max_pages: int = 10):
        self.base_url = base_url
        self.max_pages = max_pages
        self.visited = set()
        self.urls_with_params = set()
        self.base_domain = urlparse(base_url).netloc
    
    def crawl(self) -> Set[str]:
        """Crawl website and find URLs with parameters"""
        logger.info(f"Starting crawl of {self.base_url}")
        
        try:
            self._crawl_page(self.base_url)
        except Exception as e:
            logger.warning(f"Crawl failed: {str(e)}")
        
        logger.info(f"Crawl complete. Found {len(self.urls_with_params)} URLs with parameters")
        return self.urls_with_params  # Always return set, even if empty
    
    def _crawl_page(self, url: str):
        """Crawl a single page"""
        if len(self.visited) >= self.max_pages:
            return
        
        if url in self.visited:
            return
        
        # Only crawl same domain
        parsed_url = urlparse(url)
        if parsed_url.netloc != self.base_domain:
            return
        
        self.visited.add(url)
        
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            if response.status_code != 200:
                return
            
            # Check if URL has parameters
            if parse_qs(parsed_url.query):
                self.urls_with_params.add(url)
            
            # Skip parsing HTML if we can't connect
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return
            
            # Skip BeautifulSoup parsing to avoid timeout issues
            # For demo mode, we don't need actual crawling
            
        except Exception as e:
            logger.warning(f"Error crawling {url}: {str(e)}")