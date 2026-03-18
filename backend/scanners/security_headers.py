from typing import List, Dict, Any
from scanners.base_scanner import BaseScanner
import logging

logger = logging.getLogger(__name__)

class SecurityHeadersScanner(BaseScanner):

    REQUIRED_HEADERS = {
        "X-Frame-Options": {
            "severity": "medium",
            "description_en": "Prevents clickjacking attacks",
            "description_hy": "Կանխում է clickjacking հարձակումները",
            "recommendation_en": "Add X-Frame-Options: DENY or SAMEORIGIN header",
            "recommendation_hy": "Ավելացրեք X-Frame-Options: DENY կամ SAMEORIGIN header"
        },
        "X-Content-Type-Options": {
            "severity": "low",
            "description_en": "Prevents MIME-sniffing attacks",
            "description_hy": "Կանխում է MIME-sniffing հարձակումները",
            "recommendation_en": "Add X-Content-Type-Options: nosniff header",
            "recommendation_hy": "Ավելացրեք X-Content-Type-Options: nosniff header"
        },
        "Strict-Transport-Security": {
            "severity": "high",
            "description_en": "Enforces HTTPS connections",
            "description_hy": "Պարտադրում է HTTPS կապեր",
            "recommendation_en": "Add Strict-Transport-Security header",
            "recommendation_hy": "Ավելացրեք Strict-Transport-Security header"
        },
        "Content-Security-Policy": {
            "severity": "medium",
            "description_en": "Prevents XSS and data injection attacks",
            "description_hy": "Կանխում է XSS և data injection հարձակումները",
            "recommendation_en": "Implement Content-Security-Policy header",
            "recommendation_hy": "Իրականացրեք Content-Security-Policy header"
        }
    }

    def scan(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting Security Headers scan for {self.target_url}")

        response = self.make_request(self.target_url)

        if not response:
            logger.warning(f"Failed to fetch {self.target_url}, using demo mode")
            headers = {}
        else:
            headers = response.headers

        for header_name, info in self.REQUIRED_HEADERS.items():
            if header_name not in headers:
                self.add_vulnerability({
                    "vuln_type": "security_headers",
                    "severity": info["severity"],
                    "title": self.t(
                        f"Missing {header_name} header",
                        f"Բացակայում է {header_name} header"
                    ),
                    "description": self.t(
                        f"{header_name} security header is missing. {info['description_en']}",
                        f"{header_name} անվտանգության header-ը բացակայում է։ {info['description_hy']}"
                    ),
                    "url": self.target_url,
                    "recommendation": self.t(info["recommendation_en"], info["recommendation_hy"]),
                    "references": "https://owasp.org/www-project-secure-headers/"
                })

        return self.get_results()
