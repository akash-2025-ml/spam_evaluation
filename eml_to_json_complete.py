#!/usr/bin/env python3
"""
Complete Universal EML to JSON Converter
Extracts ALL attachments from ANY EML file, handles ALL edge cases
"""

import json
import email
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import base64
import quopri
import mimetypes
import binascii
from urllib.parse import urlparse


class CompleteEMLToJSONConverter:
    """Universal converter that handles ALL EML formats and attachment types"""
    
    def __init__(self, tenant_id: str = "2a9c5f75-c7ee-4b9f-9ccc-626ddcbd786a"):
        self.tenant_id = tenant_id
    
    def convert_eml_to_json(self, eml_path: str, mailbox_id: str = None) -> Dict[str, Any]:
        """Convert ANY EML file to JSON with ALL attachments"""
        
        # Read file once
        with open(eml_path, 'rb') as f:
            raw_bytes = f.read()
        
        # Parse email
        try:
            msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        except:
            # Create empty message if parsing fails
            msg = email.message.EmailMessage()
        
        # Extract all data
        message_id = Path(eml_path).stem
        
        # Get sender
        sender_info = self._extract_email_address(msg.get('From', ''))
        
        # Get mailbox
        if not mailbox_id:
            mailbox_id = self._determine_mailbox(msg, sender_info)
        
        # Get recipients
        to_recipients = self._parse_recipients(msg.get('To', ''))
        cc_recipients = self._parse_recipients(msg.get('Cc', ''))
        bcc_recipients = self._parse_recipients(msg.get('Bcc', ''))
        reply_to = self._parse_recipients(msg.get('Reply-To', ''))
        
        # Get body
        body_content, content_type, html_content = self._extract_body(msg, raw_bytes)
        
        # Extract links and domains
        links = self._extract_links(body_content, html_content)
        domains = self._extract_domains(links)
        
        # Get headers
        headers = self._extract_headers(msg)
        
        # EXTRACT ALL ATTACHMENTS
        attachments = self._extract_all_attachments(msg, raw_bytes)
        
        # Build JSON
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
                    "sender": {"emailAddress": sender_info},
                    "from": {"emailAddress": sender_info},
                    "toRecipients": to_recipients,
                    "ccRecipients": cc_recipients,
                    "bccRecipients": bcc_recipients,
                    "replyTo": reply_to,
                    "receivedDateTime": self._parse_datetime(msg.get('Date', '')),
                    "sentDateTime": self._parse_datetime(msg.get('Date', '')),
                    "body": {
                        "contentType": content_type,
                        "content": body_content[:10000]
                    },
                    "hasAttachments": len(attachments) > 0,
                    "internetMessageId": msg.get('Message-ID', ''),
                    "importance": self._get_importance(msg),
                    "isRead": False,
                    "isDraft": False,
                    "flag": {"flagStatus": "notFlagged"}
                },
                "headers": headers,
                "payload": {
                    "content": self._extract_plain_text(body_content, content_type)[:1000],
                    "links": links,
                    "domain": domains
                }
            }
        }
        
        # Add attachments if found
        if attachments:
            json_data["email_data"]["attachments"] = attachments
        
        return json_data
    
    def _extract_email_address(self, email_str: str) -> Dict[str, str]:
        """Extract email address"""
        if not email_str:
            return {"name": "", "address": ""}
        name, address = parseaddr(email_str)
        return {"name": name or "", "address": address or email_str.strip('<>')}
    
    def _parse_recipients(self, recipients: str) -> List[Dict[str, Dict[str, str]]]:
        """Parse recipient list"""
        if not recipients:
            return []
        
        result = []
        for recipient in re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', recipients):
            recipient = recipient.strip()
            if recipient:
                result.append({"emailAddress": self._extract_email_address(recipient)})
        return result
    
    def _determine_mailbox(self, msg, sender_info) -> str:
        """Determine mailbox ID"""
        # Try Delivered-To
        delivered_to = msg.get('Delivered-To', '')
        if delivered_to:
            return self._extract_email_address(delivered_to)['address']
        
        # Try first To recipient
        to_header = msg.get('To', '')
        if to_header:
            recipients = self._parse_recipients(to_header)
            if recipients:
                return recipients[0]['emailAddress']['address']
        
        # Default
        return "unknown@example.com"
    
    def _extract_body(self, msg, raw_bytes) -> tuple:
        """Extract body content from any format"""
        body = ""
        content_type = "text"
        html_content = ""
        
        try:
            # Standard extraction
            if msg.is_multipart():
                text_parts = []
                html_parts = []
                
                for part in msg.walk():
                    if part.get_content_maintype() == 'multipart':
                        continue
                    
                    ct = part.get_content_type()
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            text = payload.decode('utf-8', errors='ignore')
                        else:
                            text = part.get_payload()
                    except:
                        text = str(part.get_payload())
                    
                    if ct == "text/plain":
                        text_parts.append(text)
                    elif ct == "text/html":
                        html_parts.append(text)
                
                if text_parts:
                    body = '\n'.join(text_parts)
                elif html_parts:
                    body = '\n'.join(html_parts)
                    content_type = "html"
                    html_content = body
            else:
                # Single part
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='ignore')
                    else:
                        body = msg.get_payload()
                except:
                    body = str(msg.get_payload())
                
                if msg.get_content_type() == "text/html":
                    content_type = "html"
                    html_content = body
        
        except:
            # Fallback to raw parsing
            content = raw_bytes.decode('latin-1', errors='ignore')
            # Extract text from raw MIME
            text_match = re.search(r'Content-Type: text/plain.*?\n\n(.*?)(?=\n--|\Z)', content, re.DOTALL)
            if text_match:
                body = text_match.group(1).strip()
        
        # Clean up non-standard MIME artifacts
        if isinstance(body, str) and 'This is a multipart MIME message' in body:
            # Remove MIME structure
            parts = re.split(r'--[^\n]+\n', body)
            for part in parts:
                if part.strip() and not 'Content-' in part:
                    body = part.strip()
                    break
        
        return body or "", content_type, html_content
    
    def _extract_links(self, text_content: str, html_content: str) -> List[str]:
        """Extract all links"""
        links = []
        
        # From HTML
        if html_content:
            href_links = re.findall(r'href=[\'"]?([^\'" >]+)', html_content, re.IGNORECASE)
            links.extend(href_links)
        
        # From any text
        content = html_content or text_content
        if content:
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            urls = re.findall(url_pattern, content)
            links.extend(urls)
        
        # Deduplicate
        return list(dict.fromkeys(links))
    
    def _extract_domains(self, links: List[str]) -> List[str]:
        """Extract domains from links"""
        domains = []
        for link in links:
            try:
                domain = urlparse(link).netloc.lower()
                if domain and domain not in domains:
                    domains.append(domain)
            except:
                pass
        return domains
    
    def _extract_plain_text(self, content: str, content_type: str) -> str:
        """Convert to plain text"""
        if not content:
            return ""
        
        if content_type == "html":
            # Remove HTML tags
            text = re.sub(r'<[^>]+>', ' ', content)
            text = re.sub(r'\s+', ' ', text)
            return text.strip()
        return content
    
    def _parse_datetime(self, date_str: str) -> str:
        """Parse date safely"""
        if not date_str:
            return datetime.utcnow().isoformat() + "Z"
        try:
            dt = parsedate_to_datetime(date_str)
            return dt.isoformat()
        except:
            return datetime.utcnow().isoformat() + "Z"
    
    def _get_importance(self, msg) -> str:
        """Get importance"""
        importance = msg.get('Importance', '').lower()
        priority = msg.get('X-Priority', '').lower()
        
        if 'high' in importance or priority.startswith('1'):
            return "high"
        elif 'low' in importance or priority.startswith('5'):
            return "low"
        return "normal"
    
    def _extract_headers(self, msg) -> Dict[str, Any]:
        """Extract all headers with fallbacks"""
        # Get received headers
        received = msg.get_all('Received', []) or []
        
        # Extract IPs
        ips = []
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        for header in received:
            if header:
                found_ips = re.findall(ip_pattern, header)
                for ip in found_ips:
                    if ip not in ips and not ip.startswith(('127.', '10.', '192.168.')):
                        ips.append(ip)
        
        # Get SMTP server
        smtp = ""
        if received:
            match = re.search(r'from\s+([^\s\(]+)', received[0])
            if match:
                smtp = match.group(1).strip('[]')
        
        # Return path with fallbacks
        return_path = msg.get('Return-Path', '').strip('<>')
        if not return_path:
            return_path = msg.get('Reply-To', '').strip('<>')
        if not return_path:
            return_path = self._extract_email_address(msg.get('From', '')).get('address', '')
        
        # Authentication
        auth = msg.get('Authentication-Results', '')
        spf = "pass" if "spf=pass" in auth else ("fail" if "spf=fail" in auth else "")
        dkim = "pass" if "dkim=pass" in auth else ("fail" if "dkim=fail" in auth else "")
        dmarc = "pass" if "dmarc=pass" in auth else ("fail" if "dmarc=fail" in auth else "")
        
        # List unsubscribe
        list_unsub = msg.get('List-Unsubscribe', '')
        urls = re.findall(r'<(https?://[^>]+)>', list_unsub)
        mailtos = [m.split('?')[0] for m in re.findall(r'<mailto:([^>]+)>', list_unsub)]
        
        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "returnpath": return_path,
            "ipaddress": ips[:10],
            "smtpserver": smtp,
            "tlsversion": "",
            "list_unsubscribe_urls": urls,
            "list_unsubscribe_mailtos": mailtos,
            "list_unsubscribe_one_click": msg.get('List-Unsubscribe-Post') == 'List-Unsubscribe=One-Click'
        }
    
    def _extract_all_attachments(self, msg, raw_bytes) -> List[Dict[str, Any]]:
        """Extract ALL attachments using multiple methods"""
        attachments = []
        found_names = set()
        
        # Method 1: Standard email library
        try:
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                
                # Check if attachment
                filename = part.get_filename()
                disp = str(part.get('Content-Disposition', ''))
                ct = part.get_content_type()
                cid = part.get('Content-ID', '')
                
                is_attachment = (
                    filename or
                    'attachment' in disp or
                    'inline' in disp and not ct.startswith('text/') or
                    cid or
                    (not ct.startswith('text/') and not ct.startswith('multipart/'))
                )
                
                if is_attachment:
                    # Get content
                    try:
                        payload = part.get_payload(decode=True)
                        if payload is None:
                            payload = b''
                    except:
                        payload = str(part.get_payload()).encode('utf-8', errors='ignore')
                    
                    # Get name
                    if not filename:
                        # Try Content-Type name
                        ct_header = part.get('Content-Type', '')
                        match = re.search(r'name=["\']?([^"\';\n]+)', ct_header)
                        if match:
                            filename = match.group(1).strip()
                        else:
                            ext = mimetypes.guess_extension(ct) or '.bin'
                            filename = f"attachment_{len(attachments)}{ext}"
                    
                    att = {
                        "name": filename,
                        "contentBytes": base64.b64encode(payload).decode('ascii'),
                        "contentType": ct
                    }
                    
                    if cid:
                        att["contentId"] = cid.strip('<>')
                    
                    attachments.append(att)
                    found_names.add(filename)
                    
        except Exception as e:
            print(f"Standard extraction error: {e}")
        
        # Method 2: Raw parsing for non-standard formats
        try:
            content = raw_bytes.decode('latin-1', errors='ignore')
            
            # Find all boundaries
            boundaries = set()
            
            # From headers
            for match in re.finditer(r'boundary=["\']?([^"\';\n]+)', content, re.I):
                boundaries.add(match.group(1))
            
            # From content (more reliable)
            potential = re.findall(r'^(--[^\r\n]+)$', content, re.MULTILINE)
            bound_counts = {}
            for b in potential:
                clean = b.rstrip('-')
                if len(clean) > 2:
                    bound_counts[clean] = bound_counts.get(clean, 0) + 1
            
            for b, count in bound_counts.items():
                if count >= 2:
                    boundaries.add(b[2:])  # Remove --
            
            # Process each boundary
            for boundary in boundaries:
                parts = re.split(f'--{re.escape(boundary)}(?:--)?\\r?\\n', content)
                
                for part in parts[1:]:
                    if not part.strip():
                        continue
                    
                    # Split headers/body
                    match = re.match(r'^(.*?)\\r?\\n\\r?\\n(.*)$', part, re.DOTALL)
                    if not match:
                        continue
                    
                    headers_str, body = match.groups()
                    
                    # Parse headers
                    headers = {}
                    for line in headers_str.split('\\n'):
                        if ':' in line:
                            k, v = line.split(':', 1)
                            headers[k.strip()] = v.strip()
                    
                    ct = headers.get('Content-Type', '')
                    cd = headers.get('Content-Disposition', '')
                    
                    # Skip text without attachment marker
                    if ct.startswith('text/') and 'attachment' not in cd and 'name=' not in ct:
                        continue
                    
                    # Get filename
                    filename = None
                    for h in [cd, ct]:
                        match = re.search(r'(?:file)?name=["\']?([^"\';\n]+)', h, re.I)
                        if match:
                            filename = match.group(1).strip()
                            break
                    
                    if not filename:
                        ext = mimetypes.guess_extension(ct.split(';')[0]) or '.bin'
                        filename = f"extracted_{len(attachments)}{ext}"
                    
                    # Skip if already found
                    if filename in found_names:
                        continue
                    
                    # Decode content
                    encoding = headers.get('Content-Transfer-Encoding', '').lower()
                    decoded = self._decode_content(body.strip(), encoding)
                    
                    if decoded:
                        att = {
                            "name": filename,
                            "contentBytes": base64.b64encode(decoded).decode('ascii'),
                            "contentType": ct.split(';')[0].strip() or "application/octet-stream"
                        }
                        
                        cid = headers.get('Content-ID', '').strip('<>')
                        if cid:
                            att["contentId"] = cid
                        
                        attachments.append(att)
                        found_names.add(filename)
        
        except Exception as e:
            print(f"Raw extraction error: {e}")
        
        return attachments
    
    def _decode_content(self, content: str, encoding: str) -> bytes:
        """Decode any encoding"""
        try:
            if encoding == 'base64':
                clean = re.sub(r'\\s+', '', content)
                pad = len(clean) % 4
                if pad:
                    clean += '=' * (4 - pad)
                return base64.b64decode(clean)
            elif encoding == 'quoted-printable':
                return quopri.decodestring(content.encode('ascii', errors='ignore'))
            else:
                return content.encode('latin-1', errors='ignore')
        except:
            return content.encode('utf-8', errors='ignore')


# Main function
def main():
    """Interactive converter"""
    print("Complete Universal EML to JSON Converter")
    print("Extracts ALL attachments from ANY EML file\\n")
    
    eml_file = input("Enter EML file path: ").strip()
    
    if not Path(eml_file).exists():
        print(f"File not found: {eml_file}")
        return
    
    converter = CompleteEMLToJSONConverter()
    
    try:
        print(f"\\nConverting {eml_file}...")
        json_data = converter.convert_eml_to_json(eml_file)
        
        # Save
        output = Path(eml_file).stem + "_complete.json"
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Saved to: {output}")
        
        # Summary
        att = json_data['email_data'].get('attachments', [])
        print(f"✓ Found {len(att)} attachment(s)")
        for a in att:
            print(f"  - {a['name']} ({a['contentType']})")
    
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()