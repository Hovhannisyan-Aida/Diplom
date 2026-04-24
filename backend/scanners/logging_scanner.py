from typing import List, Dict, Any
from scanners.base_scanner import BaseScanner
from urllib.parse import urljoin
import re
import logging

logger = logging.getLogger(__name__)

class LoggingMonitoringScanner(BaseScanner):

    SENSITIVE_PATHS = [
        '/admin', '/administrator', '/admin/login', '/admin/dashboard', '/admin/console',
        '/debug', '/debug/vars', '/debug/pprof',
        '/logs', '/log', '/error.log', '/access.log', '/application.log', '/debug.log',
        '/.git/config', '/.git/HEAD', '/.svn/entries', '/.env', '/.env.local',
        '/actuator', '/actuator/env', '/actuator/logfile', '/actuator/trace',
        '/actuator/heapdump', '/actuator/mappings',
        '/metrics', '/prometheus',
        '/phpinfo.php', '/info.php', '/test.php',
        '/console', '/h2-console', '/manager/html',
        '/wp-admin/', '/wp-login.php',
        '/server-status', '/server-info',
        '/trace',
    ]

    ERROR_TRIGGER_PATHS = [
        '/this-page-does-not-exist-xyz-12345',
        "/api/undefined/trigger/error",
    ]

    STACK_TRACE_PATTERNS = [
        r'traceback \(most recent call last\)',
        r'file ".*\.py", line \d+',
        r'at \w+\.\w+\([\w.]+:\d+\)',
        r'caused by:',
        r'exception in thread',
        r'stack trace:',
        r'#\d+ \w+\.php\(\d+\)',
        r'fatal error:.*in.*on line \d+',
        r'parse error:.*in.*on line \d+',
        r'system\.web\.httpexception',
        r'server error in.*application',
        r'django\.core\.exceptions',
        r'activerecord::',
        r'illuminate\\',
    ]

    CRITICAL_PATHS = {
        '/.git/config', '/.git/HEAD', '/.svn/entries',
        '/.env', '/.env.local',
        '/actuator/env', '/actuator/heapdump', '/actuator/logfile',
        '/h2-console',
    }

    def scan(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting Logging & Monitoring scan for {self.target_url}")

        response = self.make_request(self.target_url)
        if response:
            self._check_version_disclosure(response)
            self._check_technology_in_body(response)
            self._check_error_pages()

        self._check_sensitive_endpoints()

        logger.info(f"Logging & Monitoring scan finished, found {len(self.results)} vulnerabilities")
        return self.get_results()

    def _check_version_disclosure(self, response):
        headers = response.headers

        server = headers.get('Server', '')
        if server and re.search(r'\d+\.\d+', server):
            self.add_vulnerability({
                'vuln_type': 'logging_monitoring',
                'severity': 'medium',
                'title': self.t(
                    'Server Version Disclosed in Header',
                    'Սերվերի տարբերակը բացահայտված է Header-ում',
                    'Версия сервера раскрыта в заголовке'
                ),
                'description': self.t(
                    f'The "Server" header reveals the server software and version: "{server}". '
                    f'This helps attackers identify known vulnerabilities for that specific version.',
                    f'"Server" header-ը բացահայտում է սերվերի ծրագրաշարը և տարբերակը՝ "{server}"։ '
                    f'Սա օգնում է հարձակվողներին հայտնաբերել հայտնի խոցելիություններ տվյալ տարբերակի համար։',
                    f'Заголовок "Server" раскрывает ПО и версию сервера: "{server}". '
                    f'Это помогает злоумышленникам выявить известные уязвимости для конкретной версии.'
                ),
                'url': self.target_url,
                'evidence': f'Server: {server}',
                'recommendation': self.t(
                    'Configure the server to suppress or genericize the Server header (e.g. "Server: webserver").',
                    'Կարգավորեք սերվերը Server header-ը թաքցնելու կամ ընդհանրացնելու համար (օրինակ՝ "Server: webserver")։',
                    'Настройте сервер для скрытия заголовка Server (например, "Server: webserver").'
                ),
                'references': 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
            })

        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            self.add_vulnerability({
                'vuln_type': 'logging_monitoring',
                'severity': 'medium',
                'title': self.t(
                    'Technology Stack Disclosed via X-Powered-By Header',
                    'Տեխնոլոգիան բացահայտված է X-Powered-By Header-ի միջոցով',
                    'Технологический стек раскрыт через заголовок X-Powered-By'
                ),
                'description': self.t(
                    f'The "X-Powered-By" header reveals the backend technology: "{powered_by}". '
                    f'Attackers can use this to target known vulnerabilities in that technology.',
                    f'"X-Powered-By" header-ը բացահայտում է backend տեխնոլոգիան՝ "{powered_by}"։ '
                    f'Հարձակվողները կարող են օգտագործել դա տվյալ տեխնոլոգիայի հայտնի խոցելիությունները թիրախավորելու համար։',
                    f'Заголовок "X-Powered-By" раскрывает серверную технологию: "{powered_by}". '
                    f'Злоумышленники могут использовать это для атак на известные уязвимости данной технологии.'
                ),
                'url': self.target_url,
                'evidence': f'X-Powered-By: {powered_by}',
                'recommendation': self.t(
                    'Remove the X-Powered-By header from all responses.',
                    'Հեռացրեք X-Powered-By header-ը բոլոր response-ներից։',
                    'Удалите заголовок X-Powered-By из всех ответов.'
                ),
                'references': 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
            })

        for header_name in ['X-AspNet-Version', 'X-AspNetMvc-Version']:
            value = headers.get(header_name, '')
            if value:
                self.add_vulnerability({
                    'vuln_type': 'logging_monitoring',
                    'severity': 'medium',
                    'title': self.t(
                        f'Framework Version Disclosed via {header_name} Header',
                        f'Framework-ի տարբերակը բացահայտված է {header_name} Header-ի միջոցով',
                        f'Версия фреймворка раскрыта через заголовок {header_name}'
                    ),
                    'description': self.t(
                        f'The "{header_name}" header reveals the ASP.NET version: "{value}". '
                        f'Attackers can use this to find version-specific vulnerabilities.',
                        f'"{header_name}" header-ը բացահայտում է ASP.NET տարբերակը՝ "{value}"։ '
                        f'Հարձակվողները կարող են օգտագործել դա version-specific խոցելիություններ գտնելու համար։',
                        f'Заголовок "{header_name}" раскрывает версию ASP.NET: "{value}". '
                        f'Злоумышленники могут использовать это для поиска версионных уязвимостей.'
                    ),
                    'url': self.target_url,
                    'evidence': f'{header_name}: {value}',
                    'recommendation': self.t(
                        f'Remove the {header_name} header via web.config or server configuration.',
                        f'Հեռացրեք {header_name} header-ը web.config-ի կամ սերվերի կարգավորումների միջոցով։',
                        f'Удалите заголовок {header_name} через web.config или настройки сервера.'
                    ),
                    'references': 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
                })

    def _check_technology_in_body(self, response):
        body = response.text
        body_lower = body.lower()

        meta_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if not meta_match:
            meta_match = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', body, re.IGNORECASE)

        if meta_match:
            generator = meta_match.group(1).strip()
            logger.info(f"Generator meta tag found: {generator}")
            self.add_vulnerability({
                'vuln_type': 'logging_monitoring',
                'severity': 'low',
                'title': self.t(
                    f'CMS/Framework Version Disclosed via Meta Tag',
                    f'CMS/Framework-ի տարբերակը բացահայտված է Meta Tag-ի միջոցով',
                    f'Версия CMS/фреймворка раскрыта через мета-тег'
                ),
                'description': self.t(
                    f'The page contains a generator meta tag revealing the technology and version: "{generator}". '
                    f'This helps attackers identify known vulnerabilities for that version.',
                    f'Էջը պարունակում է generator meta tag, որը բացահայտում է տեխնոլոգիան և տարբերակը՝ "{generator}"։ '
                    f'Սա օգնում է հարձակվողներին հայտնաբերել տվյալ տարբերակի հայտնի խոցելիությունները։',
                    f'Страница содержит мета-тег generator, раскрывающий технологию и версию: "{generator}". '
                    f'Это помогает злоумышленникам найти известные уязвимости для данной версии.'
                ),
                'url': self.target_url,
                'evidence': f'<meta name="generator" content="{generator}">',
                'recommendation': self.t(
                    'Remove or suppress the generator meta tag in your CMS/framework settings.',
                    'Հեռացրեք կամ թաքցրեք generator meta tag-ը ձեր CMS/framework-ի կարգավորումներում։',
                    'Удалите или скройте мета-тег generator в настройках вашей CMS/фреймворка.'
                ),
                'references': 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
            })

        tech_signatures = {
            'wp-content': 'WordPress',
            'wp-includes': 'WordPress',
            'joomla': 'Joomla',
            'drupal': 'Drupal',
            'laravel': 'Laravel',
            '/sites/default/': 'Drupal',
        }
        for signature, tech in tech_signatures.items():
            if signature in body_lower:
                if not any(v.get('evidence', '').startswith('<meta') for v in self.results):
                    logger.info(f"Technology signature found: {tech} ({signature})")
                    self.add_vulnerability({
                        'vuln_type': 'logging_monitoring',
                        'severity': 'low',
                        'title': self.t(
                            f'Technology Fingerprint Detected: {tech}',
                            f'Տեխնոլոգիայի հետք հայտնաբերվեց՝ {tech}',
                            f'Обнаружен технологический отпечаток: {tech}'
                        ),
                        'description': self.t(
                            f'The page HTML contains signatures identifying the platform as {tech} ("{signature}" found in source). '
                            f'Knowing the exact platform helps attackers search for known CVEs.',
                            f'Էջի HTML-ը պարունակում է {tech} հարթակը նույնականացնող ստորագրություններ ("{signature}" գտնվեց source-ում)։ '
                            f'Հարթակի ճշգրիտ իմացությունը օգնում է հարձակվողներին փնտրել հայտնի CVE-ներ։',
                            f'HTML страницы содержит признаки платформы {tech} ("{signature}" найдено в источнике). '
                            f'Знание платформы помогает злоумышленникам искать известные CVE.'
                        ),
                        'url': self.target_url,
                        'evidence': f'Signature "{signature}" found in page source',
                        'recommendation': self.t(
                            f'Keep {tech} updated to the latest version and remove or obscure identifying signatures where possible.',
                            f'Թարմացրեք {tech}-ը վերջին տարբերակին և հնարավորության դեպքում հեռացրեք կամ թաքցրեք նույնականացնող ստորագրությունները։',
                            f'Обновите {tech} до последней версии и по возможности удалите или скройте идентифицирующие признаки.'
                        ),
                        'references': 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
                    })
                break

    def _check_error_pages(self):
        for path in self.ERROR_TRIGGER_PATHS:
            url = urljoin(self.target_url, path)
            response = self.make_request(url)
            if not response:
                continue

            body_lower = response.text.lower()
            for pattern in self.STACK_TRACE_PATTERNS:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    logger.info(f"Verbose error page detected at {url}")
                    self.add_vulnerability({
                        'vuln_type': 'logging_monitoring',
                        'severity': 'high',
                        'title': self.t(
                            'Verbose Error Page — Stack Trace Exposed',
                            'Մանրամասն Սխալի Էջ — Stack Trace-ը Բացահայտված Է',
                            'Подробная страница ошибки — трассировка стека раскрыта'
                        ),
                        'description': self.t(
                            f'The server returns a verbose error page with internal details (stack trace, file paths, '
                            f'or framework information) when an invalid request is sent to "{url}". '
                            f'This leaks internal application structure to attackers.',
                            f'Սերվերը վերադարձնում է մանրամասն սխալի էջ ներքին մանրամասներով (stack trace, ֆայլի ուղիներ '
                            f'կամ framework-ի տեղեկատվություն) "{url}" անվավեր հարցման դեպքում։ '
                            f'Սա բացահայտում է հավելվածի ներքին կառուցվածքը հարձակվողներին։',
                            f'Сервер возвращает подробную страницу ошибки с внутренними деталями (трассировка стека, '
                            f'пути файлов или информация о фреймворке) при неверном запросе к "{url}". '
                            f'Это раскрывает внутреннюю структуру приложения злоумышленникам.'
                        ),
                        'url': url,
                        'recommendation': self.t(
                            'Disable debug mode in production. Configure custom error pages that return only generic messages.',
                            'Անջատեք debug ռեժիմը production-ում։ Կարգավորեք custom error pages, որոնք ցուցադրում են միայն ընդհանուր հաղորդագրություններ։',
                            'Отключите режим отладки в production. Настройте пользовательские страницы ошибок с общими сообщениями.'
                        ),
                        'references': 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
                    })
                    return

    def _check_sensitive_endpoints(self):
        base = self.target_url.rstrip('/')
        found_count = 0

        for path in self.SENSITIVE_PATHS:
            if found_count >= 5:
                break

            url = base + path
            response = self.make_request(url)
            if response is None:
                continue

            status = response.status_code
            is_open = status == 200
            is_protected = status in (401, 403) and path in self.CRITICAL_PATHS

            if not is_open and not is_protected:
                continue

            logger.info(f"Sensitive endpoint found: {url} (HTTP {status})")

            if is_open:
                severity = self._severity_for_path(path)
                title = self.t(
                    f'Sensitive Endpoint Publicly Accessible: {path}',
                    f'Զգայուն Endpoint-ը Հրապարակայնորեն Հասանելի Է՝ {path}',
                    f'Чувствительный эндпоинт общедоступен: {path}'
                )
                description = self.t(
                    f'The {self._categorize_path(path)} endpoint "{url}" returned HTTP 200 and is fully accessible. '
                    f'This may expose sensitive configuration, internal logs, or application internals.',
                    f'{self._categorize_path(path)} endpoint-ը "{url}" վերադարձրեց HTTP 200 և լիովին հասանելի է։ '
                    f'Սա կարող է բացահայտել զգայուն կարգավորումներ, logs կամ հավելվածի ներքին տվյալներ։',
                    f'Эндпоинт {self._categorize_path(path)} "{url}" вернул HTTP 200 и полностью доступен. '
                    f'Это может раскрыть конфиденциальную конфигурацию, внутренние логи или данные приложения.'
                )
            else:
                severity = 'high'
                title = self.t(
                    f'Sensitive File Exists on Server (Access Restricted): {path}',
                    f'Զգայուն ֆայլը գոյություն ունի սերվերում (հասանելիությունը սահմանափակված է)՝ {path}',
                    f'Чувствительный файл существует на сервере (доступ ограничен): {path}'
                )
                description = self.t(
                    f'The server returned HTTP {status} for "{url}", confirming the file or endpoint exists '
                    f'but is access-restricted. The resource should not exist on a production server at all.',
                    f'Սերվերը վերադարձրեց HTTP {status} "{url}"-ի համար, հաստատելով, որ ֆայլը կամ endpoint-ը գոյություն ունի, '
                    f'բայց հասանելիությունը սահմանափակված է։ Այս resource-ը ընդհանրապես չպետք է գոյություն ունենա production սերվերում։',
                    f'Сервер вернул HTTP {status} для "{url}", подтверждая существование файла или эндпоинта '
                    f'при ограниченном доступе. Этого ресурса вообще не должно быть на production-сервере.'
                )

            self.add_vulnerability({
                'vuln_type': 'logging_monitoring',
                'severity': severity,
                'title': title,
                'description': description,
                'url': url,
                'evidence': f'HTTP {status} from {url}',
                'recommendation': self.t(
                    f'Remove "{path}" from the server entirely. Never deploy source control files, '
                    f'.env files, or debug endpoints to production.',
                    f'Ամբողջությամբ հեռացրեք "{path}"-ը սերվերից։ Երբեք մի տեղակայեք source control ֆայլեր, '
                    f'.env ֆայլեր կամ debug endpoint-ներ production-ում։',
                    f'Полностью удалите "{path}" с сервера. Никогда не развёртывайте файлы системы контроля версий, '
                    f'.env файлы или отладочные эндпоинты на production.'
                ),
                'references': 'https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'
            })
            found_count += 1

    def _categorize_path(self, path: str) -> str:
        if any(p in path for p in ['/admin', '/administrator', '/console', '/manager']):
            return 'admin panel'
        if any(p in path for p in ['/log', '/error.log', '/access.log', '/debug.log']):
            return 'log file'
        if any(p in path for p in ['/.git', '/.svn', '/.env']):
            return 'sensitive file'
        if any(p in path for p in ['/actuator', '/metrics', '/prometheus', '/trace']):
            return 'monitoring/metrics'
        if any(p in path for p in ['/phpinfo', '/info.php', '/test.php']):
            return 'debug info'
        if '/debug' in path:
            return 'debug'
        return 'sensitive'

    def _severity_for_path(self, path: str) -> str:
        if any(p in path for p in ['/.git', '/.env', '/actuator/env', '/actuator/heapdump', '/h2-console']):
            return 'critical'
        if any(p in path for p in ['/admin', '/administrator', '/console', '/manager', '/actuator', '/phpinfo']):
            return 'high'
        return 'medium'
