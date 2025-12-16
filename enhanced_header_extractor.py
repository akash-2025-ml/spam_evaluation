#!/usr/bin/env python3
"""
Enhanced Header Extraction for EML Files
Extracts authentication headers and provides default values when missing
"""

import re
from typing import Dict, List, Optional


class HeaderExtractor:
    def __init__(self):
        self.auth_patterns = {
            'spf': [
                r'spf=(\w+)',
                r'Received-SPF:\s*(\w+)',
                r'SPF:\s*(\w+)'
            ],
            'dkim': [
                r'dkim=(\w+)',
                r'DKIM-Signature:.*?([a-z]+)=',
                r'dkim-signature:.*?([a-z]+)='
            ],
            'dmarc': [
                r'dmarc=(\w+)',
                r'DMARC:\s*(\w+)'
            ]
        }
    
    def extract_authentication_results(self, msg) -> Dict[str, str]:
        """Extract SPF, DKIM, DMARC from Authentication-Results header"""
        results = {
            'spf': '',
            'dkim': '',
            'dmarc': ''
        }
        
        # Look for Authentication-Results header
        auth_results = msg.get('Authentication-Results', '')
        if not auth_results:
            # Try alternate header names
            auth_results = msg.get('X-Authentication-Results', '') or \
                          msg.get('ARC-Authentication-Results', '')
        
        if auth_results:
            # Extract SPF
            for pattern in self.auth_patterns['spf']:
                match = re.search(pattern, auth_results, re.IGNORECASE)
                if match:
                    results['spf'] = match.group(1).lower()
                    break
            
            # Extract DKIM
            for pattern in self.auth_patterns['dkim']:
                match = re.search(pattern, auth_results, re.IGNORECASE)
                if match:
                    results['dkim'] = match.group(1).lower()
                    break
            
            # Extract DMARC
            for pattern in self.auth_patterns['dmarc']:
                match = re.search(pattern, auth_results, re.IGNORECASE)
                if match:
                    results['dmarc'] = match.group(1).lower()
                    break
        
        # Check individual headers if not found in Authentication-Results
        if not results['spf']:
            received_spf = msg.get('Received-SPF', '')
            if received_spf:
                match = re.match(r'^(\w+)', received_spf.strip())
                if match:
                    results['spf'] = match.group(1).lower()
        
        if not results['dkim']:
            # Check if DKIM-Signature exists (indicates DKIM was used)
            if msg.get('DKIM-Signature'):
                results['dkim'] = 'signed'  # We know it was signed, but not the verification result
        
        return results
    
    def extract_return_path(self, msg) -> str:
        """Extract Return-Path with multiple fallback options"""
        # Primary: Return-Path header
        return_path = msg.get('Return-Path', '').strip('<>')
        
        if not return_path:
            # Fallback 1: Reply-To header
            reply_to = msg.get('Reply-To', '')
            if reply_to:
                # Extract email from Reply-To
                match = re.search(r'<([^>]+)>', reply_to)
                if match:
                    return_path = match.group(1)
                else:
                    # Simple email pattern
                    match = re.search(r'[\w\.-]+@[\w\.-]+', reply_to)
                    if match:
                        return_path = match.group(0)
        
        if not return_path:
            # Fallback 2: From header
            from_header = msg.get('From', '')
            match = re.search(r'<([^>]+)>', from_header)
            if match:
                return_path = match.group(1)
            else:
                # Simple email pattern
                match = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
                if match:
                    return_path = match.group(0)
        
        if not return_path:
            # Fallback 3: Sender header
            sender = msg.get('Sender', '').strip('<>')
            if sender:
                return_path = sender
        
        return return_path
    
    def extract_ip_addresses(self, received_headers: List[str]) -> List[str]:
        """Extract IP addresses from Received headers with improved regex"""
        ip_addresses = []
        
        # Improved IP regex pattern
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        for header in received_headers:
            # Find all IP addresses in the header
            ips = re.findall(ip_pattern, header)
            for ip in ips:
                if ip not in ip_addresses:
                    # Filter out common local/private IPs
                    if not (ip.startswith('127.') or 
                           ip.startswith('10.') or 
                           ip.startswith('192.168.') or
                           ip.startswith('172.')):
                        ip_addresses.append(ip)
        
        # Also check X-Originating-IP header
        if not ip_addresses:
            x_originating_ip = msg.get('X-Originating-IP', '')
            if x_originating_ip:
                # Extract IP from brackets [1.2.3.4]
                match = re.search(r'\[(' + ip_pattern + r')\]', x_originating_ip)
                if match:
                    ip_addresses.append(match.group(1))
        
        return ip_addresses[:10]  # Limit to 10 IPs
    
    def extract_list_unsubscribe(self, msg) -> Dict[str, any]:
        """Extract List-Unsubscribe headers"""
        result = {
            'list_unsubscribe_urls': [],
            'list_unsubscribe_mailtos': [],
            'list_unsubscribe_one_click': False
        }
        
        # Get List-Unsubscribe header
        list_unsub = msg.get('List-Unsubscribe', '')
        if list_unsub:
            # Extract URLs
            urls = re.findall(r'<(https?://[^>]+)>', list_unsub)
            result['list_unsubscribe_urls'] = urls
            
            # Extract mailto links
            mailtos = re.findall(r'<mailto:([^>]+)>', list_unsub)
            # Clean up mailto addresses (remove parameters)
            clean_mailtos = []
            for mailto in mailtos:
                email = mailto.split('?')[0]
                if email and email not in clean_mailtos:
                    clean_mailtos.append(email)
            result['list_unsubscribe_mailtos'] = clean_mailtos
        
        # Check for one-click unsubscribe
        if msg.get('List-Unsubscribe-Post') == 'List-Unsubscribe=One-Click':
            result['list_unsubscribe_one_click'] = True
        
        return result
    
    def extract_smtp_and_tls(self, received_headers: List[str]) -> Dict[str, str]:
        """Extract SMTP server and TLS version from headers"""
        result = {
            'smtpserver': '',
            'tlsversion': ''
        }
        
        if received_headers:
            # Get SMTP server from first Received header
            first_received = received_headers[0]
            
            # Extract SMTP server
            match = re.search(r'from\s+([^\s\(]+)', first_received)
            if match:
                result['smtpserver'] = match.group(1).strip('[]')
            
            # Look for TLS version
            for header in received_headers:
                # Common TLS version patterns
                tls_match = re.search(r'(?:with\s+ESMTPS?.*?|using\s+)TLSv?([\d\.]+)', header, re.IGNORECASE)
                if tls_match:
                    result['tlsversion'] = f"TLSv{tls_match.group(1)}"
                    break
                
                # Check for generic TLS mention
                if 'TLS' in header and not result['tlsversion']:
                    result['tlsversion'] = 'TLS'
        
        return result
    
    def get_enhanced_headers(self, msg, received_headers: List[str]) -> Dict[str, any]:
        """Get all enhanced headers with fallbacks"""
        # Get authentication results
        auth_results = self.extract_authentication_results(msg)
        
        # Get other header information
        smtp_tls = self.extract_smtp_and_tls(received_headers)
        list_unsub = self.extract_list_unsubscribe(msg)
        
        return {
            'spf': auth_results['spf'],
            'dkim': auth_results['dkim'],
            'dmarc': auth_results['dmarc'],
            'returnpath': self.extract_return_path(msg),
            'ipaddress': self.extract_ip_addresses(received_headers),
            'smtpserver': smtp_tls['smtpserver'],
            'tlsversion': smtp_tls['tlsversion'],
            'list_unsubscribe_urls': list_unsub['list_unsubscribe_urls'],
            'list_unsubscribe_mailtos': list_unsub['list_unsubscribe_mailtos'],
            'list_unsubscribe_one_click': list_unsub['list_unsubscribe_one_click']
        }


# Example usage
if __name__ == "__main__":
    import email
    from email import policy
    
    # Test with an EML file
    with open('00022.eml', 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    
    extractor = HeaderExtractor()
    received_headers = msg.get_all('Received', [])
    headers = extractor.get_enhanced_headers(msg, received_headers)
    
    print("Extracted headers:")
    for key, value in headers.items():
        print(f"  {key}: {value}")