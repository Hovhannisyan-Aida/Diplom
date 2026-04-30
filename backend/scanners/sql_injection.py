from typing import List, Dict, Any
from scanners.base_scanner import BaseScanner
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
import logging
import time

logger = logging.getLogger(__name__)

class SQLInjectionScanner(BaseScanner):

    ERROR_PAYLOADS = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "' AND 1=2--",
    ]

    TIME_PAYLOADS = [
        "' OR SLEEP(4)--",
        "'; WAITFOR DELAY '0:0:4'--",
    ]

    TRUE_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
    ]

    FALSE_PAYLOADS = [
        "' AND '1'='2",
        "' AND 1=2--",
    ]

    ERROR_SIGNATURES = [
        "sql syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "mysql_result",
        "mysql error",
        "ora-01",
        "sqlite",
        "syntax error",
        "unclosed quotation",
        "you have an error in your sql",
        "warning: mysql",
        "invalid query",
        "pg_query",
        "supplied argument is not a valid mysql",
        "expects parameter 1 to be resource",
        "microsoft ole db provider for sql server",
        "odbc microsoft access",
        "jdbc",
        "sqlexception",
    ]

    def scan(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting SQL Injection scan for {self.target_url}")

        baseline_start = time.time()
        baseline_response = self.make_request(self.target_url)
        self.baseline_time = time.time() - baseline_start
        self.time_threshold = self.baseline_time + 3.5
        self._reported_params = set()
        self._baseline_text = baseline_response.text.lower() if baseline_response else ""
        self._baseline_len = len(baseline_response.text) if baseline_response else 0
        logger.info(f"Baseline: {round(self.baseline_time, 2)}s, Time threshold: {round(self.time_threshold, 2)}s")

        self._test_url_parameters()
        self._test_forms()
        logger.info(f"SQL scan finished, found {len(self.results)} vulnerabilities")
        return self.get_results()

    def _test_url_parameters(self):
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        if params:
            for param in params:
                self._test_param_error_based(param, params, parsed)
                if param not in self._reported_params:
                    self._test_param_boolean_based(param, params, parsed)
                if param not in self._reported_params:
                    self._test_param_time_based(param, params, parsed)
        else:
            common_params = ["id", "page", "user", "search", "q", "cat", "item"]
            for param in common_params:
                self._test_common_param(param)

    def _test_param_error_based(self, param, params, parsed):
        for payload in self.ERROR_PAYLOADS:
            new_params = params.copy()
            new_params[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
            response = self.make_request(test_url)
            if response and self._detect_sql_error(response.text):
                logger.info(f"Error-based SQL Injection in URL param '{param}'")
                self._reported_params.add(param)
                self._report(
                    param=param, method="GET", payload=payload, url=test_url,
                    detection="Error-based", evidence="SQL error signature found in response"
                )
                return

    def _test_param_boolean_based(self, param, params, parsed):
        for true_payload, false_payload in zip(self.TRUE_PAYLOADS, self.FALSE_PAYLOADS):
            new_params_true = params.copy()
            new_params_true[param] = [true_payload]
            true_url = urlunparse(parsed._replace(query=urlencode(new_params_true, doseq=True)))

            new_params_false = params.copy()
            new_params_false[param] = [false_payload]
            false_url = urlunparse(parsed._replace(query=urlencode(new_params_false, doseq=True)))

            true_resp = self.make_request(true_url)
            false_resp = self.make_request(false_url)

            if not true_resp or not false_resp:
                continue

            direct_diff = abs(len(true_resp.text) - len(false_resp.text))
            true_vs_baseline = abs(len(true_resp.text) - self._baseline_len)

            if direct_diff > 500 and true_vs_baseline < 300:
                logger.info(f"Boolean-based SQL Injection in URL param '{param}' direct_diff={direct_diff} true_vs_baseline={true_vs_baseline}")
                self._reported_params.add(param)
                self._report(
                    param=param, method="GET",
                    payload=f"{true_payload} / {false_payload}",
                    url=true_url, detection="Boolean-based",
                    evidence=f"TRUE/FALSE response size difference: {direct_diff}B (true_vs_baseline: {true_vs_baseline}B)"
                )
                return

    def _test_param_time_based(self, param, params, parsed):
        for payload in self.TIME_PAYLOADS:
            new_params = params.copy()
            new_params[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))
            start = time.time()
            response = self.make_request(test_url)
            elapsed = time.time() - start
            if response and elapsed > self.time_threshold:
                start2 = time.time()
                self.make_request(test_url)
                elapsed2 = time.time() - start2
                if elapsed2 > self.time_threshold:
                    logger.info(f"Time-based SQL Injection in URL param '{param}' elapsed={elapsed:.2f}s confirmed={elapsed2:.2f}s")
                    self._reported_params.add(param)
                    self._report(
                        param=param, method="GET", payload=payload, url=test_url,
                        detection="Time-based",
                        evidence=f"Response time: {round(elapsed, 2)}s, confirmed: {round(elapsed2, 2)}s (baseline: {round(self.baseline_time, 2)}s)"
                    )
                    return

    def _test_common_param(self, param):
        # Error-based
        for payload in self.ERROR_PAYLOADS:
            test_url = f"{self.target_url}?{param}={payload}"
            response = self.make_request(test_url)
            if response and self._detect_sql_error(response.text):
                logger.info(f"Error-based SQL Injection in common param '{param}'")
                self._reported_params.add(param)
                self._report(
                    param=param, method="GET", payload=payload, url=test_url,
                    detection="Error-based", evidence="SQL error signature found in response"
                )
                return

        # Boolean-based
        if param not in self._reported_params:
            for true_payload, false_payload in zip(self.TRUE_PAYLOADS, self.FALSE_PAYLOADS):
                true_url = f"{self.target_url}?{param}={true_payload}"
                false_url = f"{self.target_url}?{param}={false_payload}"
                true_resp = self.make_request(true_url)
                false_resp = self.make_request(false_url)
                if not true_resp or not false_resp:
                    continue
                direct_diff = abs(len(true_resp.text) - len(false_resp.text))
                true_vs_baseline = abs(len(true_resp.text) - self._baseline_len)
                if direct_diff > 500 and true_vs_baseline < 300:
                    logger.info(f"Boolean-based SQL Injection in common param '{param}' direct_diff={direct_diff} true_vs_baseline={true_vs_baseline}")
                    self._reported_params.add(param)
                    self._report(
                        param=param, method="GET",
                        payload=f"{true_payload} / {false_payload}",
                        url=true_url, detection="Boolean-based",
                        evidence=f"TRUE/FALSE response size difference: {direct_diff}B (true_vs_baseline: {true_vs_baseline}B)"
                    )
                    return

        # Time-based
        if param not in self._reported_params:
            for payload in self.TIME_PAYLOADS:
                test_url = f"{self.target_url}?{param}={payload}"
                start = time.time()
                response = self.make_request(test_url)
                elapsed = time.time() - start
                if response and elapsed > self.time_threshold:
                    start2 = time.time()
                    self.make_request(test_url)
                    elapsed2 = time.time() - start2
                    if elapsed2 > self.time_threshold:
                        logger.info(f"Time-based SQL Injection in common param '{param}' elapsed={elapsed:.2f}s confirmed={elapsed2:.2f}s")
                        self._reported_params.add(param)
                        self._report(
                            param=param, method="GET", payload=payload, url=test_url,
                            detection="Time-based",
                            evidence=f"Response time: {round(elapsed, 2)}s, confirmed: {round(elapsed2, 2)}s (baseline: {round(self.baseline_time, 2)}s)"
                        )
                        return

    def _test_forms(self):
        response = self.make_request(self.target_url)
        if not response:
            logger.warning(f"No response from {self.target_url}")
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        logger.info(f"Found {len(forms)} forms on {self.target_url}")

        form_baselines = {}

        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(self.target_url, action) if action else self.target_url

            inputs = form.find_all(['input', 'textarea'])
            form_data = {}
            for inp in inputs:
                name = inp.get('name')
                if name:
                    form_data[name] = inp.get('value', 'test')

            logger.info(f"Form: {form_url}, method: {method}, fields: {list(form_data.keys())}")
            if not form_data:
                continue

            # Cache baseline length for this form's action URL
            if form_url not in form_baselines:
                baseline_resp = self.make_request(form_url)
                form_baselines[form_url] = len(baseline_resp.text) if baseline_resp else 0
            form_baseline_len = form_baselines[form_url]

            for field in form_data:
                if field in self._reported_params:
                    logger.info(f"Skipping form field '{field}' — already reported")
                    continue

                # Error-based + length-diff check
                for payload in self.ERROR_PAYLOADS:
                    test_data = {**form_data, field: payload}
                    resp = self.make_request(
                        form_url,
                        method='POST' if method == 'post' else 'GET',
                        **({'data': test_data} if method == 'post' else {'params': test_data})
                    )
                    if not resp:
                        continue
                    len_diff = abs(len(resp.text) - form_baseline_len) if form_baseline_len > 0 else 0
                    sql_error = self._detect_sql_error(resp.text)
                    large_diff = len_diff > 500

                    if sql_error or large_diff:
                        detection = "Error-based" if sql_error else "Length-difference"
                        evidence = (
                            "SQL error signature found in response" if sql_error
                            else f"Response length changed by {len_diff}B (baseline: {form_baseline_len}B)"
                        )
                        logger.info(f"{detection} SQL Injection in form field '{field}' (len_diff={len_diff})")
                        self._reported_params.add(field)
                        self._report(
                            param=field, method=method.upper(), payload=payload, url=form_url,
                            detection=detection, evidence=evidence, title_key="form"
                        )
                        break

                if field in self._reported_params:
                    continue

                # Boolean-based check
                for true_payload, false_payload in zip(self.TRUE_PAYLOADS, self.FALSE_PAYLOADS):
                    true_data = {**form_data, field: true_payload}
                    false_data = {**form_data, field: false_payload}
                    req_kwargs = {'data': true_data} if method == 'post' else {'params': true_data}
                    true_resp = self.make_request(form_url, method='POST' if method == 'post' else 'GET', **req_kwargs)
                    req_kwargs = {'data': false_data} if method == 'post' else {'params': false_data}
                    false_resp = self.make_request(form_url, method='POST' if method == 'post' else 'GET', **req_kwargs)

                    if not true_resp or not false_resp:
                        continue

                    direct_diff = abs(len(true_resp.text) - len(false_resp.text))
                    true_vs_baseline = abs(len(true_resp.text) - form_baseline_len) if form_baseline_len > 0 else 0

                    if direct_diff > 500 and true_vs_baseline < 300:
                        logger.info(f"Boolean-based SQL Injection in form field '{field}' direct_diff={direct_diff} true_vs_baseline={true_vs_baseline}")
                        self._reported_params.add(field)
                        self._report(
                            param=field, method=method.upper(),
                            payload=f"{true_payload} / {false_payload}",
                            url=form_url, detection="Boolean-based",
                            evidence=f"TRUE/FALSE response size difference: {direct_diff}B (true_vs_baseline: {true_vs_baseline}B)",
                            title_key="form"
                        )
                        break

                if field in self._reported_params:
                    continue

                # Time-based check
                for payload in self.TIME_PAYLOADS:
                    test_data = {**form_data, field: payload}
                    start = time.time()
                    resp = self.make_request(
                        form_url,
                        method='POST' if method == 'post' else 'GET',
                        **({'data': test_data} if method == 'post' else {'params': test_data})
                    )
                    elapsed = time.time() - start
                    if resp and elapsed > self.time_threshold:
                        start2 = time.time()
                        self.make_request(
                            form_url,
                            method='POST' if method == 'post' else 'GET',
                            **({'data': test_data} if method == 'post' else {'params': test_data})
                        )
                        elapsed2 = time.time() - start2
                        if elapsed2 > self.time_threshold:
                            logger.info(f"Time-based SQL Injection in form field '{field}' elapsed={elapsed:.2f}s confirmed={elapsed2:.2f}s")
                            self._reported_params.add(field)
                            self._report(
                                param=field, method=method.upper(), payload=payload, url=form_url,
                                detection="Time-based",
                                evidence=f"Response time: {round(elapsed, 2)}s, confirmed: {round(elapsed2, 2)}s (baseline: {round(self.baseline_time, 2)}s)",
                                title_key="form"
                            )
                            break

    def _report(self, param, method, payload, url, detection, evidence, title_key="param"):
        if title_key == "form":
            title_en = f"SQL Injection vulnerability in form field '{param}'"
            title_hy = f"SQL Injection խոցելիություն form-ի '{param}' դաշտում"
            desc_en = f"SQL injection detected in form field '{param}' ({method}). {detection}."
            desc_hy = f"SQL injection հայտնաբերված form-ի '{param}' դաշտում ({method})։ {detection}։"
        else:
            title_en = f"SQL Injection vulnerability in parameter '{param}'"
            title_hy = f"SQL Injection խոցելիություն '{param}' պարամետրում"
            desc_en = f"SQL injection detected in '{param}' parameter ({method}). {detection}."
            desc_hy = f"SQL injection հայտնաբերված '{param}' պարամետրում ({method})։ {detection}։"

        self.add_vulnerability({
            "vuln_type": "sql_injection",
            "severity": "critical",
            "title": self.t(title_en, title_hy),
            "description": self.t(desc_en, desc_hy),
            "url": url,
            "parameter": param,
            "method": method,
            "payload": payload,
            "evidence": evidence,
            "recommendation": self.t(
                "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
                "Օգտագործեք parameterized queries կամ prepared statements։ Երբեք մի միացրեք օգտատիրոջ input-ը SQL հարցումներին։",
                "Используйте параметризованные запросы или подготовленные выражения. Никогда не конкатенируйте пользовательский ввод в SQL-запросы."
            ),
            "references": "https://owasp.org/www-community/attacks/SQL_Injection"
        })

    def _detect_sql_error(self, response_text: str) -> bool:
        response_lower = response_text.lower()
        for signature in self.ERROR_SIGNATURES:
            if signature in response_lower and signature not in self._baseline_text:
                return True
        return False
