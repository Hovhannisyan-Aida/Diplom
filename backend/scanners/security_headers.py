import re
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
            "description_ru": "Предотвращает атаки кликджекинга",
            "recommendation_en": "Add X-Frame-Options: DENY or SAMEORIGIN header",
            "recommendation_hy": "Ավելացրեք X-Frame-Options: DENY կամ SAMEORIGIN գլխագիրը",
            "recommendation_ru": "Добавьте заголовок X-Frame-Options: DENY или SAMEORIGIN"
        },
        "X-Content-Type-Options": {
            "severity": "low",
            "description_en": "Prevents MIME-sniffing attacks",
            "description_hy": "Կանխում է MIME-sniffing հարձակումները",
            "description_ru": "Предотвращает атаки MIME-сниффинга",
            "recommendation_en": "Add X-Content-Type-Options: nosniff header",
            "recommendation_hy": "Ավելացրեք X-Content-Type-Options: nosniff գլխագիրը",
            "recommendation_ru": "Добавьте заголовок X-Content-Type-Options: nosniff"
        },
        "Strict-Transport-Security": {
            "severity": "high",
            "description_en": "Enforces HTTPS connections",
            "description_hy": "Պարտադրում է HTTPS միացումներ",
            "description_ru": "Обеспечивает принудительное использование HTTPS",
            "recommendation_en": "Add Strict-Transport-Security header",
            "recommendation_hy": "Ավելացրեք Strict-Transport-Security գլխագիրը",
            "recommendation_ru": "Добавьте заголовок Strict-Transport-Security"
        },
        "Content-Security-Policy": {
            "severity": "medium",
            "description_en": "Prevents XSS and data injection attacks",
            "description_hy": "Կանխում է XSS և տվյալների ներարկման (injection) հարձակումները",
            "description_ru": "Предотвращает XSS и атаки внедрения данных",
            "recommendation_en": "Implement Content-Security-Policy header",
            "recommendation_hy": "Ներդրեք Content-Security-Policy գլխագիրը",
            "recommendation_ru": "Внедрите заголовок Content-Security-Policy"
        }
    }

    def scan(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting Security Headers scan for {self.target_url}")

        response = self.make_request(self.target_url)

        if not response:
            logger.warning(f"Failed to fetch {self.target_url}, skipping security headers scan")
            return self.get_results()

        headers = response.headers

        for header_name, info in self.REQUIRED_HEADERS.items():
            if header_name not in headers:
                self.add_vulnerability({
                    "vuln_type": "security_headers",
                    "severity": info["severity"],
                    "title": self.t(
                        f"Missing {header_name} header",
                        f"Բացակայում է {header_name} գլխագիրը",
                        f"Отсутствует заголовок {header_name}"
                    ),
                    "description": self.t(
                        f"{header_name} security header is missing. {info['description_en']}",
                        f"{header_name} անվտանգության գլխագիրը բացակայում է։ {info['description_hy']}",
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
            else:
                self._validate_value(header_name, headers[header_name])

        return self.get_results()

    def _validate_value(self, header_name: str, value: str):
        value_stripped = value.strip()

        if header_name == "X-Frame-Options":
            if value_stripped.upper() not in ("DENY", "SAMEORIGIN"):
                self.add_vulnerability({
                    "vuln_type": "security_headers",
                    "severity": "medium",
                    "title": self.t(
                        "Weak X-Frame-Options Value",
                        "X-Frame-Options-ի թույլ արժեք",
                        "Слабое значение X-Frame-Options"
                    ),
                    "description": self.t(
                        f"X-Frame-Options header is present but has an invalid value '{value_stripped}'. "
                        "Only DENY or SAMEORIGIN are valid.",
                        f"X-Frame-Options գլխագիրն առկա է, բայց ունի անվավեր արժեք '{value_stripped}'։ "
                        "Վավեր են միայն DENY կամ SAMEORIGIN արժեքները։",
                        f"Заголовок X-Frame-Options присутствует, но имеет недопустимое значение '{value_stripped}'. "
                        "Допустимы только DENY или SAMEORIGIN."
                    ),
                    "recommendation": self.t(
                        "Set X-Frame-Options to DENY (recommended) or SAMEORIGIN.",
                        "Սահմանեք X-Frame-Options-ը DENY (խորհուրդ է տրվում) կամ SAMEORIGIN:",
                        "Установите X-Frame-Options в DENY (рекомендуется) или SAMEORIGIN."
                    ),
                    "url": self.target_url,
                    "references": "https://owasp.org/www-project-secure-headers/"
                })

        elif header_name == "X-Content-Type-Options":
            if value_stripped.lower() != "nosniff":
                self.add_vulnerability({
                    "vuln_type": "security_headers",
                    "severity": "low",
                    "title": self.t(
                        "Weak X-Content-Type-Options Value",
                        "X-Content-Type-Options-ի թույլ արժեք",
                        "Слабое значение X-Content-Type-Options"
                    ),
                    "description": self.t(
                        f"X-Content-Type-Options header is present but its value '{value_stripped}' is not 'nosniff'.",
                        f"X-Content-Type-Options գլխագիրն առկա է, բայց դրա արժեքը '{value_stripped}' 'nosniff' չէ։",
                        f"Заголовок X-Content-Type-Options присутствует, но его значение '{value_stripped}' не является 'nosniff'."
                    ),
                    "recommendation": self.t(
                        "Set X-Content-Type-Options: nosniff",
                        "Սահմանեք X-Content-Type-Options: nosniff",
                        "Установите X-Content-Type-Options: nosniff"
                    ),
                    "url": self.target_url,
                    "references": "https://owasp.org/www-project-secure-headers/"
                })

        elif header_name == "Strict-Transport-Security":
            match = re.search(r'max-age\s*=\s*(\d+)', value_stripped, re.IGNORECASE)
            if match:
                max_age = int(match.group(1))
                if max_age < 31536000:
                    self.add_vulnerability({
                        "vuln_type": "security_headers",
                        "severity": "medium",
                        "title": self.t(
                            "Weak Strict-Transport-Security — Short max-age",
                            "Թույլ HSTS — max-age-ի փոքր արժեք",
                            "Слабый HSTS — короткий max-age"
                        ),
                        "description": self.t(
                            f"HSTS header is present but max-age is {max_age} seconds, "
                            "which is less than 1 year (31536000 seconds). Short max-age reduces protection.",
                            f"HSTS գլխագիրն առկա է, բայց max-age-ը {max_age} վայրկյան է, "
                            "ինչը 1 տարուց պակաս է (31536000 վայրկյան)։ Կարճ max-age-ը նվազեցնում է պաշտպանվածությունը։",
                            f"Заголовок HSTS присутствует, но max-age равен {max_age} секундам, "
                            "что меньше 1 года (31536000 секунд). Короткий max-age снижает защиту."
                        ),
                        "recommendation": self.t(
                            "Set max-age to at least 31536000 (1 year). Consider adding includeSubDomains.",
                            "Սահմանեք max-age-ը առնվազն 31536000 (1 տարի)։ Դիտարկեք includeSubDomains-ի ավելացումը։",
                            "Установите max-age не менее 31536000 (1 год). Рассмотрите добавление includeSubDomains."
                        ),
                        "url": self.target_url,
                        "references": "https://owasp.org/www-project-secure-headers/"
                    })

        elif header_name == "Content-Security-Policy":
            self._validate_csp(value_stripped)

    def _validate_csp(self, csp_value: str):
        checks = [
            (
                "'unsafe-inline'",
                "'unsafe-inline'" in csp_value,
                self.t(
                    "Content-Security-Policy contains 'unsafe-inline' which allows inline scripts and undermines XSS protection.",
                    "Content-Security-Policy-ն պարունակում է 'unsafe-inline', ինչը թույլատրում է ներդրված սկրիպտներ և թուլացնում XSS պաշտպանությունը։",
                    "Content-Security-Policy содержит 'unsafe-inline', что разрешает встроенные скрипты и подрывает защиту от XSS."
                )
            ),
            (
                "'unsafe-eval'",
                "'unsafe-eval'" in csp_value,
                self.t(
                    "Content-Security-Policy contains 'unsafe-eval' which allows eval() and similar functions, enabling code injection.",
                    "Content-Security-Policy-ն պարունակում է 'unsafe-eval', ինչը թույլատրում է eval() ֆունկցիան և նմանատիպ հնարավորությունները՝ նպաստելով կոդի ներարկմանը։",
                    "Content-Security-Policy содержит 'unsafe-eval', что разрешает eval() и подобные функции, открывая возможность для внедрения кода."
                )
            ),
            (
                "wildcard *",
                bool(re.search(r"(default-src|script-src|style-src|connect-src)\s[^;]*\*", csp_value)),
                self.t(
                    "Content-Security-Policy uses a wildcard (*) in a critical directive, allowing resources from any origin.",
                    "Content-Security-Policy-ն օգտագործում է wildcard (*) կրիտիկական դիրեկտիվներում՝ թույլատրելով ռեսուրսներ ցանկացած աղբյուրից։",
                    "Content-Security-Policy использует wildcard (*) в критической директиве, разрешая ресурсы из любого источника."
                )
            ),
        ]

        for label, triggered, description in checks:
            if triggered:
                self.add_vulnerability({
                    "vuln_type": "security_headers",
                    "severity": "medium",
                    "title": self.t(
                        "Unsafe Content-Security-Policy",
                        "Ոչ անվտանգ Content-Security-Policy",
                        "Небезопасный Content-Security-Policy"
                    ),
                    "description": description,
                    "recommendation": self.t(
                        "Remove 'unsafe-inline', 'unsafe-eval', and wildcard (*) directives from Content-Security-Policy.",
                        "Հեռացրեք 'unsafe-inline', 'unsafe-eval' և wildcard (*) դիրեկտիվները Content-Security-Policy-ից։",
                        "Удалите директивы 'unsafe-inline', 'unsafe-eval' и wildcard (*) из Content-Security-Policy."
                    ),
                    "url": self.target_url,
                    "references": "https://owasp.org/www-project-secure-headers/"
                })
