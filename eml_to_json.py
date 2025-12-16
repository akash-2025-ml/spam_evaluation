#!/usr/bin/env python3
"""
Standalone EML to JSON Converter
All-in-one script - no dependencies on other files
"""

import json
import email
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
import re
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse


class EMLToJSONConverter:
    def __init__(self, tenant_id: str = "2a9c5f75-c7ee-4b9f-9ccc-626ddcbd786a"):
        self.tenant_id = tenant_id
        
    def extract_email_address(self, email_str: str) -> Dict[str, str]:
        """Extract name and address from email string"""
        name, address = parseaddr(email_str)
        return {
            "name": name or "",
            "address": address or email_str
        }
    
    def parse_recipient_list(self, recipients: Optional[str]) -> List[Dict[str, Dict[str, str]]]:
        """Parse recipient list from header"""
        if not recipients:
            return []
        
        result = []
        recipients_list = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', recipients)
        
        for recipient in recipients_list:
            recipient = recipient.strip()
            if recipient:
                result.append({
                    "emailAddress": self.extract_email_address(recipient)
                })
        return result
    
    def extract_links_from_html(self, html_content: str) -> List[str]:
        """Extract all links from HTML content"""
        links = []
        href_pattern = r'href\s*=\s*[\'"]?([^\'" >]+)'
        links.extend(re.findall(href_pattern, html_content, re.IGNORECASE))
        
        src_pattern = r'src\s*=\s*[\'"]?([^\'" >]+)'
        links.extend(re.findall(src_pattern, html_content, re.IGNORECASE))
        
        links = [link for link in links if not link.startswith('mailto:')]
        return list(set(links))
    
    def extract_domains_from_links(self, links: List[str]) -> List[str]:
        """Extract unique domains from links"""
        domains = []
        for link in links:
            try:
                parsed = urlparse(link)
                if parsed.netloc:
                    domains.append(parsed.netloc)
                elif parsed.path and not parsed.scheme:
                    domain = parsed.path.split('/')[0]
                    if '.' in domain:
                        domains.append(domain)
            except:
                continue
        return list(set(domains))
    
    def get_body_content(self, msg: email.message.EmailMessage) -> tuple:
        """Extract body content and type from email message"""
        text_content = ""
        html_content = ""
        content_type = "text"
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type_header = part.get_content_type()
                if content_type_header == "text/plain":
                    try:
                        text_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    except:
                        text_content = str(part.get_payload())
                elif content_type_header == "text/html":
                    try:
                        html_content = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        content_type = "html"
                    except:
                        html_content = str(part.get_payload())
        else:
            content_type_header = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                if content_type_header == "text/html":
                    html_content = payload
                    content_type = "html"
                else:
                    text_content = payload
            except:
                text_content = str(msg.get_payload())
        
        content = html_content if html_content else text_content
        return content, content_type, html_content
    
    def extract_plain_text(self, content: str, content_type: str) -> str:
        """Extract plain text from content"""
        if content_type == "html":
            text = re.sub(r'<[^>]+>', ' ', content)
            text = re.sub(r'\s+', ' ', text)
            return text.strip()
        return content.strip()
    
    def parse_datetime(self, date_str: Optional[str]) -> str:
        """Parse datetime string to ISO format"""
        if not date_str:
            return datetime.utcnow().isoformat() + "Z"
        
        try:
            dt = parsedate_to_datetime(date_str)
            return dt.isoformat().replace('+00:00', 'Z')
        except:
            return datetime.utcnow().isoformat() + "Z"
    
    def get_importance(self, msg: email.message.EmailMessage) -> str:
        """Determine email importance"""
        importance = msg.get('X-Priority', '').strip()
        if importance in ['1', '2']:
            return 'high'
        elif importance in ['4', '5']:
            return 'low'
        return 'normal'
    
    def extract_ip_addresses(self, received_headers: List[str]) -> List[str]:
        """Extract IP addresses from Received headers"""
        ips = []
        ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]|\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)'
        
        for header in received_headers:
            matches = re.findall(ip_pattern, header)
            for match in matches:
                ip = match[0] or match[1]
                if ip:
                    ips.append(ip)
        
        return list(set(ips))[:2]
    
    def convert_eml_to_json(self, eml_path: str, mailbox_id: str = None) -> Dict[str, Any]:
        """Convert EML file to JSON format"""
        with open(eml_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        
        message_id = os.path.splitext(os.path.basename(eml_path))[0]
        
        from_header = msg.get('From', '')
        sender_info = self.extract_email_address(from_header)
        
        if not mailbox_id:
            delivered_to = msg.get('Delivered-To', '')
            if delivered_to:
                mailbox_id = self.extract_email_address(delivered_to)['address']
            else:
                to_header = msg.get('To', '')
                if to_header:
                    to_recipients = self.parse_recipient_list(to_header)
                    if to_recipients:
                        mailbox_id = to_recipients[0]['emailAddress']['address']
                else:
                    mailbox_id = "unknown@example.com"
        
        body_content, content_type, html_content = self.get_body_content(msg)
        
        links = []
        if html_content:
            links = self.extract_links_from_html(html_content)
        domains = self.extract_domains_from_links(links)
        
        plain_text = self.extract_plain_text(body_content, content_type)
        
        received_headers = msg.get_all('Received', [])
        ip_addresses = self.extract_ip_addresses(received_headers)
        
        smtp_server = ""
        if received_headers:
            match = re.search(r'from\s+([^\s]+)', received_headers[0])
            if match:
                smtp_server = match.group(1)
        
        return_path = msg.get('Return-Path', '').strip('<>')
        
        has_attachments = False
        if msg.is_multipart():
            for part in msg.walk():
                disposition = part.get('Content-Disposition', '')
                if 'attachment' in disposition:
                    has_attachments = True
                    break
        
        json_data = {
            "tenant_id": self.tenant_id,
            "mailbox_id": mailbox_id,
            "message_id": message_id,
            "force_override": True,
            "test_mode": True,
            "email_data": {
                "id": message_id,
                "emailcontent": {
                    "subject": msg.get('Subject', ''),
                    "sender": {
                        "emailAddress": sender_info
                    },
                    "from": {
                        "emailAddress": sender_info
                    },
                    "toRecipients": self.parse_recipient_list(msg.get('To', '')),
                    "ccRecipients": self.parse_recipient_list(msg.get('Cc', '')),
                    "bccRecipients": self.parse_recipient_list(msg.get('Bcc', '')),
                    "replyTo": self.parse_recipient_list(msg.get('Reply-To', '')),
                    "receivedDateTime": self.parse_datetime(msg.get('Date', '')),
                    "sentDateTime": self.parse_datetime(msg.get('Date', '')),
                    "body": {
                        "contentType": content_type,
                        "content": body_content[:10000]
                    },
                    "hasAttachments": has_attachments,
                    "internetMessageId": msg.get('Message-ID', ''),
                    "importance": self.get_importance(msg),
                    "isRead": False,
                    "isDraft": False,
                    "flag": {"flagStatus": "notFlagged"}
                },
                "headers": {
                    "spf": "",
                    "dkim": "",
                    "dmarc": "",
                    "returnpath": return_path,
                    "ipaddress": ip_addresses,
                    "smtpserver": smtp_server,
                    "tlsversion": "",
                    "list_unsubscribe_urls": [],
                    "list_unsubscribe_mailtos": [],
                    "list_unsubscribe_one_click": False
                },
                "payload": {
                    "content": ' '.join(plain_text.split())[:1000],
                    "links": links,
                    "domain": domains
                }
            }
        }
        
        return json_data


def main():
    # Get EML file path from user
    eml_path = input("Enter the path to the EML file: ").strip()
    
    # Check if file exists
    if not os.path.exists(eml_path):
        print(f"Error: File '{eml_path}' not found!")
        return
    
    if not eml_path.lower().endswith('.eml'):
        print("Error: File must have .eml extension!")
        return
    
    # Create converter
    converter = EMLToJSONConverter()
    
    try:
        # Convert EML to JSON
        print(f"Converting {eml_path}...")
        json_data = converter.convert_eml_to_json(eml_path)
        
        # Create output filename
        output_path = eml_path.rsplit('.', 1)[0] + '_output.txt'
        
        # Save to text file
        with open(output_path, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        print(f"✓ Successfully converted!")
        print(f"✓ JSON saved to: {output_path}")
        
    except Exception as e:
        print(f"Error converting file: {e}")


if __name__ == "__main__":
    main()