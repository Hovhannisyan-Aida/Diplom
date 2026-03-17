from typing import List, Dict, Any
from scanners.base_scanner import BaseScanner
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
import logging
import time

logger = logging.getLogger(__name__)

class SQLInjectionScanner(BaseScanner):
    
    PAYLOADS = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' OR SLEEP(3)--",
        "'; WAITFOR DELAY '0:0:3'--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "' AND 1=2--",
    ]
    
    ERROR_SIGNATURES = [
        "sql syntax",
        "mysql_fetch",
        "mysql_num_rows",
        "mysql_result",
        "mysql error",
        "postgresql",
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
        "division by zero",
        "microsoft ole db provider for sql server",
        "odbc microsoft access",
        "jdbc",
        "sqlexception",
    ]
    
    def scan(self) -> List[Dict[str, Any]]:
        print(f"Starting SQL Injection scan for {self.target_url}", flush=True)
        
        baseline_start = time.time()
        self.make_request(self.target_url)
        self.baseline_time = time.time() - baseline_start
        self.threshold = self.baseline_time + 2.5
        print(f"Baseline: {round(self.baseline_time, 2)}s, Threshold: {round(self.threshold, 2)}s", flush=True)
        
        self._test_url_parameters()
        self._test_forms()
        print(f"SQL scan finished, found {len(self.results)} vulnerabilities", flush=True)
        return self.get_results()
    
    def _test_url_parameters(self):
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        if params:
            for param in params:
                for payload in self.PAYLOADS:
                    new_params = params.copy()
                    new_params[param] = [payload]
                    new_query = urlencode(new_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    
                    start_time = time.time()
                    response = self.make_request(test_url)
                    elapsed = time.time() - start_time
                    
                    if response and (self._detect_sql_error(response.text) or elapsed > self.threshold):
                        print(f"SQL INJECTION FOUND in param {param}! elapsed={elapsed}", flush=True)
                        self.add_vulnerability({
                            "vuln_type": "sql_injection",
                            "severity": "critical",
                            "title": f"SQL Injection խոցելիություն {param} պարամետրում",
                            "description": f"SQL injection հայտնաբերված '{param}' պարամետրում։ {'Time-based - response time: ' + str(round(elapsed, 2)) + 's' if elapsed > self.threshold else 'SQL error հայտնաբերված'}",
                            "url": test_url,
                            "parameter": param,
                            "method": "GET",
                            "payload": payload,
                            "evidence": f"{'Response time: ' + str(round(elapsed, 2)) + 's (baseline: ' + str(round(self.baseline_time, 2)) + 's)' if elapsed > self.threshold else 'SQL error signature հայտնաբերված response-ում'}",
                            "recommendation": "Օգտագործեք parameterized queries կամ prepared statements։",
                            "references": "https://owasp.org/www-community/attacks/SQL_Injection"
                        })
                        return
        else:
            common_params = ["id", "page", "user", "search", "q", "cat", "item"]
            for param in common_params:
                for payload in self.PAYLOADS:
                    test_url = f"{self.target_url}?{param}={payload}"
                    start_time = time.time()
                    response = self.make_request(test_url)
                    elapsed = time.time() - start_time
                    
                    if response and (self._detect_sql_error(response.text) or elapsed > self.threshold):
                        print(f"SQL INJECTION FOUND in param {param}! elapsed={elapsed}", flush=True)
                        self.add_vulnerability({
                            "vuln_type": "sql_injection",
                            "severity": "critical",
                            "title": f"SQL Injection խոցելիություն {param} պարամետրում",
                            "description": f"SQL injection հայտնաբերված '{param}' պարամետրում։ {'Time-based - response time: ' + str(round(elapsed, 2)) + 's' if elapsed > self.threshold else 'SQL error հայտնաբերված'}",
                            "url": test_url,
                            "parameter": param,
                            "method": "GET",
                            "payload": payload,
                            "evidence": f"{'Response time: ' + str(round(elapsed, 2)) + 's (baseline: ' + str(round(self.baseline_time, 2)) + 's)' if elapsed > self.threshold else 'SQL error signature հայտնաբերված response-ում'}",
                            "recommendation": "Օգտագործեք parameterized queries կամ prepared statements։",
                            "references": "https://owasp.org/www-community/attacks/SQL_Injection"
                        })
                        return
    
    def _test_forms(self):
        response = self.make_request(self.target_url)
        if not response:
            print(f"No response from {self.target_url}", flush=True)
            return
        
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        print(f"Found {len(forms)} forms on {self.target_url}", flush=True)
        
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
            
            print(f"Form: {form_url}, method: {method}, fields: {list(form_data.keys())}", flush=True)
            
            if not form_data:
                continue
            
            # Get normal response length for comparison
            if method == 'post':
                normal_resp = self.make_request(form_url, method='POST', data=form_data)
            else:
                normal_resp = self.make_request(form_url, method='GET', params=form_data)
            normal_length = len(normal_resp.text) if normal_resp else 0
            print(f"Normal response length: {normal_length}", flush=True)
            
            for field in form_data:
                for payload in self.PAYLOADS:
                    test_data = form_data.copy()
                    test_data[field] = payload
                    
                    start_time = time.time()
                    if method == 'post':
                        resp = self.make_request(form_url, method='POST', data=test_data)
                    else:
                        resp = self.make_request(form_url, method='GET', params=test_data)
                    elapsed = time.time() - start_time
                    
                    length_diff = abs(len(resp.text) - normal_length) if resp else 0
                    print(f"Field: {field}, payload: {payload[:20]}, elapsed: {round(elapsed,2)}s, length_diff: {length_diff}", flush=True)
                    
                    if resp and (self._detect_sql_error(resp.text) or elapsed > self.threshold or length_diff > 500):
                        print(f"SQL INJECTION FOUND in {field}! elapsed={elapsed}, length_diff={length_diff}", flush=True)
                        self.add_vulnerability({
                            "vuln_type": "sql_injection",
                            "severity": "critical",
                            "title": f"SQL Injection խոցելիություն form-ի {field} դաշտում",
                            "description": f"SQL injection հայտնաբերված form-ի '{field}' դաշտում ({method.upper()})։ {'Time-based - response time: ' + str(round(elapsed, 2)) + 's' if elapsed > self.threshold else 'Boolean-based - response length difference: ' + str(length_diff) + ' bytes' if length_diff > 500 else 'SQL error հայտնաբերված'}",
                            "url": form_url,
                            "parameter": field,
                            "method": method.upper(),
                            "payload": payload,
                            "evidence": f"Response length diff: {length_diff} bytes (normal: {normal_length}, payload: {len(resp.text) if resp else 0})",
                            "recommendation": "Օգտագործեք parameterized queries կամ prepared statements։",
                            "references": "https://owasp.org/www-community/attacks/SQL_Injection"
                        })
                        return
    
    def _detect_sql_error(self, response_text: str) -> bool:
        response_lower = response_text.lower()
        for signature in self.ERROR_SIGNATURES:
            if signature in response_lower:
                return True
        return False