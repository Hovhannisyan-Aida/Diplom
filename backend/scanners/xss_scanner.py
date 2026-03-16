from typing import List, Dict, Any
from scanners.base_scanner import BaseScanner
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
import logging

logger = logging.getLogger(__name__)

class XSSScanner(BaseScanner):
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "'><script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
    ]
    
    def scan(self) -> List[Dict[str, Any]]:
        logger.info(f"Starting XSS scan for {self.target_url}")
        
        # 1. Test URL parameters
        self._test_url_parameters()
        
        # 2. Test forms
        self._test_forms()
        
        return self.get_results()
    
    def _test_url_parameters(self):
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        all_params = list(params.keys()) if params else ["q", "search", "query", "name", "id", "page"]
        
        for param in all_params:
            for payload in self.XSS_PAYLOADS:
                if params:
                    new_params = params.copy()
                    new_params[param] = [payload]
                    new_query = urlencode(new_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                else:
                    test_url = f"{self.target_url}?{param}={payload}"
                
                response = self.make_request(test_url)
                if response and payload.lower() in response.text.lower():
                    self.add_vulnerability({
                        "vuln_type": "xss",
                        "severity": "high",
                        "title": f"Reflected XSS խոցելիություն {param} պարամետրում",
                        "description": f"XSS payload reflected է response-ում '{param}' պարամետրի միջոցով։",
                        "url": test_url,
                        "parameter": param,
                        "method": "GET",
                        "payload": payload,
                        "evidence": f"Payload հայտնաբերված response-ում՝ {payload[:50]}",
                        "recommendation": "Escape արեք բոլոր user inputs-ը։ Implement արեք CSP headers։",
                        "references": "https://owasp.org/www-community/attacks/xss/"
                    })
                    return
    
    def _test_forms(self):
        response = self.make_request(self.target_url)
        if not response:
            return
        
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        logger.info(f"Found {len(forms)} forms for XSS testing on {self.target_url}")
        
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
            
            if not form_data:
                continue
            
            for field in form_data:
                for payload in self.XSS_PAYLOADS:
                    test_data = form_data.copy()
                    test_data[field] = payload
                    
                    if method == 'post':
                        response = self.make_request(form_url, method='POST', data=test_data)
                    else:
                        response = self.make_request(form_url, method='GET', params=test_data)
                    
                    if response and payload.lower() in response.text.lower():
                        self.add_vulnerability({
                            "vuln_type": "xss",
                            "severity": "high",
                            "title": f"Reflected XSS խոցելիություն form-ի {field} դաշտում",
                            "description": f"XSS payload reflected է response-ում form-ի '{field}' դաշտի միջոցով ({method.upper()})։",
                            "url": form_url,
                            "parameter": field,
                            "method": method.upper(),
                            "payload": payload,
                            "evidence": f"Payload հայտնաբերված response-ում",
                            "recommendation": "Escape արեք բոլոր user inputs-ը։ Implement արեք CSP headers։",
                            "references": "https://owasp.org/www-community/attacks/xss/"
                        })
                        return