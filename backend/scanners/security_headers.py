from typing import List, Dict, Any
from scanners.base_scanner import BaseScanner
import logging

logger = logging.getLogger(__name__)

class SecurityHeadersScanner(BaseScanner):
    """Security headers ստուգող"""
    
    REQUIRED_HEADERS = {
        "X-Frame-Options": {
            "severity": "medium",
            "description": "Կանխում է clickjacking հարձակումները",
            "recommendation": "Ավելացրեք X-Frame-Options: DENY կամ SAMEORIGIN header"
        },
        "X-Content-Type-Options": {
            "severity": "low",
            "description": "Կանխում է MIME-sniffing հարձակումները",
            "recommendation": "Ավելացրեք X-Content-Type-Options: nosniff header"
        },
        "Strict-Transport-Security": {
            "severity": "high",
            "description": "Պարտադրում է HTTPS կապեր",
            "recommendation": "Ավելացրեք Strict-Transport-Security header"
        },
        "Content-Security-Policy": {
            "severity": "medium",
            "description": "Կանխում է XSS և data injection հարձակումները",
            "recommendation": "Իրականացրեք Content-Security-Policy header"
        }
    }
    
    def scan(self) -> List[Dict[str, Any]]:
        """Սկանավորել security headers"""
        logger.info(f"Starting Security Headers scan for {self.target_url}")
        
        response = self.make_request(self.target_url)
        
        # If request fails, use empty headers (demo mode)
        if not response:
            logger.warning(f"Failed to fetch {self.target_url}, using demo mode")
            headers = {}
        else:
            headers = response.headers
        
        for header_name, header_info in self.REQUIRED_HEADERS.items():
            if header_name not in headers:
                self.add_vulnerability({
                    "vuln_type": "security_headers",
                    "severity": header_info["severity"],
                    "title": f"Բացակայում է {header_name} header",
                    "description": f"{header_name} անվտանգության header-ը բացակայում է։ {header_info['description']}",
                    "url": self.target_url,
                    "recommendation": header_info["recommendation"],
                    "references": "https://owasp.org/www-project-secure-headers/"
                })
        
        return self.get_results()