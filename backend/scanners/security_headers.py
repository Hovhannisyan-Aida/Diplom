from typing import List, Dict, Any
from scanners.base_scanner import BaseScanner
import logging

logger = logging.getLogger(__name__)

class SecurityHeadersScanner(BaseScanner):

    REQUIRED_HEADERS = {
        "X-Frame-Options": {
            "severity": "medium",
            "description_en": "Prevents clickjacking attacks",
            "description_hy": "Կankhum է clickjacking հarjakumnerl",
            "description_ru": "Предотвращает атаки кликджекинга",
            "recommendation_en": "Add X-Frame-Options: DENY or SAMEORIGIN header",
            "recommendation_hy": "Avaelacrek X-Frame-Options: DENY կam SAMEORIGIN header",
            "recommendation_ru": "Добавьте заголовок X-Frame-Options: DENY или SAMEORIGIN"
        },
        "X-Content-Type-Options": {
            "severity": "low",
            "description_en": "Prevents MIME-sniffing attacks",
            "description_hy": "Կankhum է MIME-sniffing հarjakumnerl",
            "description_ru": "Предотвращает атаки MIME-сниффинга",
            "recommendation_en": "Add X-Content-Type-Options: nosniff header",
            "recommendation_hy": "Avaelacrek X-Content-Type-Options: nosniff header",
            "recommendation_ru": "Добавьте заголовок X-Content-Type-Options: nosniff"
        },
        "Strict-Transport-Security": {
            "severity": "high",
            "description_en": "Enforces HTTPS connections",
            "description_hy": "Partadrume է HTTPS kaperl",
            "description_ru": "Обеспечивает принудительное использование HTTPS",
            "recommendation_en": "Add Strict-Transport-Security header",
            "recommendation_hy": "Avaelacrek Strict-Transport-Security header",
            "recommendation_ru": "Добавьте заголовок Strict-Transport-Security"
        },
        "Content-Security-Policy": {
            "severity": "medium",
            "description_en": "Prevents XSS and data injection attacks",
            "description_hy": "Կankhum է XSS ev data injection harjakumnerl",
            "description_ru": "Предотвращает XSS и атаки внедрения данных",
            "recommendation_en": "Implement Content-Security-Policy header",
            "recommendation_hy": "Irkanacrek Content-Security-Policy header",
            "recommendation_ru": "Внедрите заголовок Content-Security-Policy"
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
                        f"Բacakayum e {header_name} header",
                        f"Отсутствует заголовок {header_name}"
                    ),
                    "description": self.t(
                        f"{header_name} security header is missing. {info['description_en']}",
                        f"{header_name} anvatangutyan header-y bacakayum e. {info['description_hy']}",
                        f"Заголовок безопасности {header_name} отсутствует. {info['description_ru']}"
                    ),
                    "url": self.target_url,
                    "recommendation": self.t(
                        info["recommendation_en"],
                        info["recommendation_hy"],
                        info["recommendation_ru"]
                    ),
                    "references": "https://owasp.org/www-project-secure-headers/"
                })

        return self.get_results()
