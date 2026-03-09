from typing import List, Dict, Any
from scanners.base_scanner import BaseScanner
import logging

logger = logging.getLogger(__name__)

class SQLInjectionScanner(BaseScanner):
    """SQL Injection ստուգող"""
    
    PAYLOADS = [
        "' OR '1'='1",
        "1' OR '1'='1",
        "admin'--",
        "' OR 1=1--",
    ]
    
    ERROR_SIGNATURES = [
        "sql syntax",
        "mysql",
        "postgresql",
        "ora-01",
        "sqlite",
        "syntax error",
        "unclosed quotation",
    ]
    
    def scan(self) -> List[Dict[str, Any]]:
        """Սկանավորել SQL injection"""
        logger.info(f"Starting SQL Injection scan for {self.target_url}")
        
        self._test_parameters()
        
        return self.get_results()
    
    def _test_parameters(self):
        """Թեստավորել GET պարամետրերը"""
        common_params = ["id", "page", "user", "search"]
        
        for param in common_params:
            for payload in self.PAYLOADS:
                test_url = f"{self.target_url}?{param}={payload}"
                response = self.make_request(test_url)
                
                if response and self._detect_sql_error(response.text):
                    self.add_vulnerability({
                        "vuln_type": "sql_injection",
                        "severity": "critical",
                        "title": f"SQL Injection հնարավորություն {param} պարամետրում",
                        "description": f"Հնարավոր SQL injection խոցելիություն '{param}' պարամետրում",
                        "url": test_url,
                        "parameter": param,
                        "method": "GET",
                        "payload": payload,
                        "evidence": "SQL սխալի հաղորդագրություն response-ում",
                        "recommendation": "Օգտագործեք parameterized queries կամ prepared statements։",
                        "references": "https://owasp.org/www-community/attacks/SQL_Injection"
                    })
                    break
    
    def _detect_sql_error(self, response_text: str) -> bool:
        """Հայտնաբերել SQL սխալները response-ում"""
        response_lower = response_text.lower()
        for signature in self.ERROR_SIGNATURES:
            if signature in response_lower:
                return True
        return False