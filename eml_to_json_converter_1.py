#!/usr/bin/env python3
"""
EML to JSON Converter
Converts EML files to a specific JSON format for FastAPI requests
"""

import json
import email
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import argparse
from urllib.parse import urlparse
import base64
# import html2text


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
        # Split by comma, handling quoted strings
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
        # Extract href links
        href_pattern = r'href\s*=\s*[\'"]?([^\'" >]+)'
        links.extend(re.findall(href_pattern, html_content, re.IGNORECASE))
        
        # Extract src links (images, scripts)
        src_pattern = r'src\s*=\s*[\'"]?([^\'" >]+)'
        links.extend(re.findall(src_pattern, html_content, re.IGNORECASE))
        
        # Filter out mailto links and clean up
        links = [link for link in links if not link.startswith('mailto:')]
        return list(set(links))  # Remove duplicates
    
    def extract_domains_from_links(self, links: List[str]) -> List[str]:
        """Extract unique domains from links"""
        domains = []
        for link in links:
            try:
                parsed = urlparse(link)
                if parsed.netloc:
                    domains.append(parsed.netloc)
                elif parsed.path and not parsed.scheme:
                    # Handle relative URLs or domains without scheme
                    domain = parsed.path.split('/')[0]
                    if '.' in domain:
                        domains.append(domain)
            except:
                continue
        return list(set(domains))  # Remove duplicates
    
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
        
        # Use HTML content if available, otherwise use text
        content = html_content if html_content else text_content
        return content, content_type, html_content
    
    def extract_plain_text(self, content: str, content_type: str) -> str:
        """Extract plain text from content"""
        if content_type == "html":
            # Simple HTML tag removal
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
        
        return list(set(ips))[:2]  # Return up to 2 unique IPs
    
    def extract_attachments(self, msg: email.message.EmailMessage) -> List[Dict[str, str]]:
        """Extract attachments from email and encode in base64"""
        attachments = []
        
        if msg.is_multipart():
            for part in msg.walk():
                # Skip multipart containers
                if part.get_content_maintype() == 'multipart':
                    continue
                
                # Skip plain text and HTML parts that are the main body
                if part.get_content_type() in ['text/plain', 'text/html'] and not part.get_filename():
                    continue
                
                disposition = part.get('Content-Disposition', '')
                content_id = part.get('Content-ID', '')
                
                # Check if this is an attachment or inline content (embedded images)
                if (disposition and ('attachment' in disposition or 'inline' in disposition)) or content_id:
                    filename = part.get_filename()
                    
                    # If no filename from header, check Content-Type
                    if not filename:
                        content_type_header = part.get('Content-Type', '')
                        if 'name=' in content_type_header:
                            # Extract filename from Content-Type header
                            match = re.search(r'name="?([^";\n]+)"?', content_type_header)
                            if match:
                                filename = match.group(1).strip()
                    
                    # If still no filename but has Content-ID, generate one
                    if not filename and content_id:
                        content_type = part.get_content_type()
                        ext = content_type.split('/')[-1] if '/' in content_type else 'dat'
                        # Clean Content-ID to use as filename
                        cid = content_id.strip('<>')
                        filename = f"embedded_{cid.split('@')[0]}.{ext}"
                    
                    if filename or content_id:
                        content_type = part.get_content_type()
                        payload = part.get_payload(decode=True)
                        
                        if payload:
                            # Encode attachment content to base64
                            content_base64 = base64.b64encode(payload).decode('utf-8')
                            
                            attachment_data = {
                                "name": filename or "unnamed_attachment",
                                "contentBytes": content_base64,
                                "contentType": content_type
                            }
                            
                            # Add Content-ID if present (for embedded images)
                            if content_id:
                                attachment_data["contentId"] = content_id.strip('<>')
                            
                            attachments.append(attachment_data)
        
        return attachments
    
    def convert_eml_to_json(self, eml_path: str, mailbox_id: str = None) -> Dict[str, Any]:
        """Convert EML file to JSON format"""
        # Read EML file
        with open(eml_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        
        # Extract message ID
        message_id = Path(eml_path).stem
        
        # Get sender information
        from_header = msg.get('From', '')
        sender_info = self.extract_email_address(from_header)
        
        # Determine mailbox_id
        if not mailbox_id:
            # Try to get from Delivered-To or To header
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
        
        # Get body content
        body_content, content_type, html_content = self.get_body_content(msg)
        
        # Extract links and domains
        links = []
        if html_content:
            links = self.extract_links_from_html(html_content)
        domains = self.extract_domains_from_links(links)
        
        # Extract plain text for payload
        plain_text = self.extract_plain_text(body_content, content_type)
        
        # Get received headers for IP extraction
        received_headers = msg.get_all('Received', [])
        ip_addresses = self.extract_ip_addresses(received_headers)
        
        # Get SMTP server from Received headers
        smtp_server = ""
        if received_headers:
            match = re.search(r'from\s+([^\s]+)', received_headers[0])
            if match:
                smtp_server = match.group(1)
        
        # Get Return-Path
        return_path = msg.get('Return-Path', '').strip('<>')
        
        # Extract attachments
        attachments = self.extract_attachments(msg)
        has_attachments = len(attachments) > 0
        
        # Build JSON structure
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
                        "content": body_content[:10000]  # Limit content size
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
                    "content": ' '.join(plain_text.split())[:1000],  # Normalized text
                    "links": links,
                    "domain": domains
                }
            }
        }
        
        # Add attachments block only if attachments exist
        if attachments:
            json_data["email_data"]["attachments"] = attachments
        
        return json_data


def main():
    parser = argparse.ArgumentParser(description='Convert EML files to JSON format')
    parser.add_argument('eml_file', help='Path to the EML file')
    parser.add_argument('-o', '--output', help='Output JSON file path')
    parser.add_argument('-m', '--mailbox', help='Mailbox ID (email address)')
    parser.add_argument('-t', '--tenant', default="2a9c5f75-c7ee-4b9f-9ccc-626ddcbd786a",
                        help='Tenant ID')
    parser.add_argument('--pretty', action='store_true', help='Pretty print JSON output')
    
    args = parser.parse_args()
    
    # Create converter
    converter = EMLToJSONConverter(tenant_id=args.tenant)
    
    try:
        # Convert EML to JSON
        json_data = converter.convert_eml_to_json(args.eml_file, args.mailbox)
        
        # Output JSON
        if args.output:
            with open(args.output, 'w') as f:
                if args.pretty:
                    json.dump(json_data, f, indent=2)
                else:
                    json.dump(json_data, f)
            print(f"JSON saved to: {args.output}")
        else:
            if args.pretty:
                print(json.dumps(json_data, indent=2))
            else:
                print(json.dumps(json_data))
                
    except Exception as e:
        print(f"Error converting EML file: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())