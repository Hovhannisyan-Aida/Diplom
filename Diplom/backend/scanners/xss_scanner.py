from typing import List, Dict, Any
from scanners.base_scanner import BaseScanner
import logging

logger = logging.getLogger(__name__)

class XSSScanner(BaseScanner):
    """XSS (Cross-Site Scripting) ստուգող"""
    
    # XSS payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    ]
    
    # XSS indicators in response
    XSS_INDICATORS = [
        "<script>alert('xss')</script>",
        "<script>alert(\"xss\")</script>",
        "onerror=alert('xss')",
        "onload=alert('xss')",
        "javascript:alert",
    ]
    
    def scan(self) -> List[Dict[str, Any]]:
        """Սկանավորել XSS խոցելիություններ"""
        logger.info(f"Starting XSS scan for {self.target_url}")
        
        self._test_reflected_xss()
        
        return self.get_results()
    
    def _test_reflected_xss(self):
        """Թեստավորել Reflected XSS"""
        common_params = ["q", "search", "query", "name", "id", "page"]
        
        for param in common_params:
            for payload in self.XSS_PAYLOADS:
                test_url = f"{self.target_url}?{param}={payload}"
                response = self.make_request(test_url)
                
                if response and self._detect_xss_in_response(response.text, payload):
                    self.add_vulnerability({
                        "vuln_type": "xss",
                        "severity": "high",
                        "title": f"Reflected XSS խոցելիություն {param} պարամետրում",
                        "description": f"Հնարավոր Reflected XSS խոցելիություն '{param}' պարամետրում։ Հարձակվողը կարող է inject անել JavaScript code։",
                        "url": test_url,
                        "parameter": param,
                        "method": "GET",
                        "payload": payload,
                        "evidence": "XSS payload-ը reflected է response-ում",
                        "recommendation": "Օգտագործեք input validation և output encoding։ Escape անեք բոլոր user input-ները։",
                        "references": "https://owasp.org/www-community/attacks/xss/"
                    })
                    break  # Found XSS, no need to test other payloads for this param
    
    def _detect_xss_in_response(self, response_text: str, payload: str) -> bool:
        """Հայտնաբերել XSS payload-ը response-ում"""
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        # Check if payload is reflected as-is
        if payload_lower in response_lower:
            return True
        
        # Check for common XSS indicators
        for indicator in self.XSS_INDICATORS:
            if indicator in response_lower:
                return True
        
        return False