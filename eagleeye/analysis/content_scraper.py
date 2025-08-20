"""
Content scraper for real-time text analysis
Extracts text content from websites, emails, and other sources
"""
import asyncio
import re
from datetime import datetime
from typing import List, Dict, Any, Optional, Union
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup
import email
from email.mime.text import MIMEText


class ContentScraper:
    """Scrapes content from various sources for text analysis"""
    
    def __init__(self, timeout: int = 10, max_content_length: int = 50000):
        self.timeout = timeout
        self.max_content_length = max_content_length
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
    
    async def scrape_url(self, url: str) -> Dict[str, Any]:
        """Scrape text content from a URL"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=self.headers)
                response.raise_for_status()
                
                content_type = response.headers.get('content-type', '').lower()
                
                if 'text/html' in content_type:
                    return await self._parse_html(response.text, url)
                elif 'text/plain' in content_type:
                    return {
                        'url': url,
                        'title': 'Plain Text',
                        'content': response.text[:self.max_content_length],
                        'links': [],
                        'forms': [],
                        'scraped_at': datetime.now(),
                        'content_type': 'text/plain'
                    }
                else:
                    return {
                        'url': url,
                        'title': 'Unsupported Content',
                        'content': '',
                        'links': [],
                        'forms': [],
                        'scraped_at': datetime.now(),
                        'content_type': content_type,
                        'error': f'Unsupported content type: {content_type}'
                    }
                    
        except Exception as e:
            return {
                'url': url,
                'title': 'Error',
                'content': '',
                'links': [],
                'forms': [],
                'scraped_at': datetime.now(),
                'error': str(e)
            }
    
    async def _parse_html(self, html: str, url: str) -> Dict[str, Any]:
        """Parse HTML content and extract relevant information"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Extract title
        title_tag = soup.find('title')
        title = title_tag.get_text().strip() if title_tag else 'No Title'
        
        # Extract main content
        content = self._extract_main_content(soup)
        
        # Extract links
        links = self._extract_links(soup, url)
        
        # Extract forms (potential phishing indicators)
        forms = self._extract_forms(soup)
        
        # Extract meta information
        meta_info = self._extract_meta_info(soup)
        
        return {
            'url': url,
            'title': title,
            'content': content[:self.max_content_length],
            'links': links,
            'forms': forms,
            'meta_info': meta_info,
            'scraped_at': datetime.now(),
            'content_type': 'text/html'
        }
    
    def _extract_main_content(self, soup: BeautifulSoup) -> str:
        """Extract main text content from HTML"""
        # Priority order for content extraction
        content_selectors = [
            'main',
            'article',
            '.content',
            '#content',
            '.main',
            '#main',
            'body'
        ]
        
        content_text = ""
        
        for selector in content_selectors:
            elements = soup.select(selector)
            if elements:
                content_text = elements[0].get_text(separator=' ', strip=True)
                break
        
        if not content_text:
            content_text = soup.get_text(separator=' ', strip=True)
        
        # Clean up whitespace
        content_text = re.sub(r'\s+', ' ', content_text)
        
        return content_text
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, str]]:
        """Extract all links from the page"""
        links = []
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            text = link.get_text(strip=True)
            
            # Convert relative URLs to absolute
            if href.startswith(('http://', 'https://')):
                full_url = href
            else:
                full_url = urljoin(base_url, href)
            
            links.append({
                'url': full_url,
                'text': text,
                'title': link.get('title', ''),
                'target': link.get('target', '')
            })
        
        return links[:50]  # Limit to first 50 links
    
    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract form information (potential phishing indicators)"""
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').lower(),
                'fields': []
            }
            
            # Extract input fields
            for input_field in form.find_all(['input', 'select', 'textarea']):
                field_info = {
                    'type': input_field.get('type', 'text'),
                    'name': input_field.get('name', ''),
                    'placeholder': input_field.get('placeholder', ''),
                    'required': input_field.has_attr('required')
                }
                form_data['fields'].append(field_info)
            
            forms.append(form_data)
        
        return forms
    
    def _extract_meta_info(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Extract meta information from HTML"""
        meta_info = {}
        
        # Extract meta tags
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property')
            content = meta.get('content')
            
            if name and content:
                meta_info[name] = content
        
        return meta_info
    
    def parse_email_content(self, email_content: str) -> Dict[str, Any]:
        """Parse email content for text analysis"""
        try:
            msg = email.message_from_string(email_content)
            
            # Extract headers
            headers = {
                'from': msg.get('From', ''),
                'to': msg.get('To', ''),
                'subject': msg.get('Subject', ''),
                'date': msg.get('Date', ''),
                'reply_to': msg.get('Reply-To', ''),
                'return_path': msg.get('Return-Path', '')
            }
            
            # Extract body content
            body_text = ""
            body_html = ""
            
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif content_type == "text/html":
                        body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            else:
                content_type = msg.get_content_type()
                payload = msg.get_payload(decode=True)
                if payload:
                    content = payload.decode('utf-8', errors='ignore')
                    if content_type == "text/html":
                        body_html = content
                    else:
                        body_text = content
            
            # If HTML content, extract text
            if body_html and not body_text:
                soup = BeautifulSoup(body_html, 'html.parser')
                body_text = soup.get_text(separator=' ', strip=True)
            
            # Extract URLs from email content
            urls = self._extract_urls_from_text(body_text + ' ' + body_html)
            
            return {
                'headers': headers,
                'subject': headers['subject'],
                'content': body_text[:self.max_content_length],
                'html_content': body_html[:self.max_content_length] if body_html else '',
                'urls': urls,
                'parsed_at': datetime.now(),
                'content_type': 'email'
            }
            
        except Exception as e:
            return {
                'headers': {},
                'subject': 'Parse Error',
                'content': email_content[:1000],  # First 1000 chars as fallback
                'html_content': '',
                'urls': [],
                'parsed_at': datetime.now(),
                'content_type': 'email',
                'error': str(e)
            }
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from plain text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`[\]]+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))  # Remove duplicates
    
    async def scrape_multiple_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scrape multiple URLs concurrently"""
        tasks = [self.scrape_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    'url': urls[i],
                    'title': 'Error',
                    'content': '',
                    'links': [],
                    'forms': [],
                    'scraped_at': datetime.now(),
                    'error': str(result)
                })
            else:
                processed_results.append(result)
        
        return processed_results
    
    def analyze_content_for_scam_indicators(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scraped content for scam indicators"""
        indicators = {
            'suspicious_forms': [],
            'suspicious_links': [],
            'urgency_indicators': 0,
            'trust_indicators': 0,
            'risk_score': 0.0
        }
        
        content = content_data.get('content', '').lower()
        
        # Check for suspicious forms
        forms = content_data.get('forms', [])
        for form in forms:
            suspicious_fields = []
            for field in form.get('fields', []):
                field_type = field.get('type', '').lower()
                field_name = field.get('name', '').lower()
                
                if field_type in ['password', 'email'] or any(keyword in field_name for keyword in ['ssn', 'social', 'credit', 'card', 'bank']):
                    suspicious_fields.append(field)
            
            if suspicious_fields:
                indicators['suspicious_forms'].append({
                    'action': form.get('action', ''),
                    'suspicious_fields': suspicious_fields
                })
        
        # Check for suspicious links
        links = content_data.get('links', [])
        for link in links:
            link_url = link.get('url', '').lower()
            link_text = link.get('text', '').lower()
            
            # Check for URL shorteners or suspicious domains
            suspicious_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
            if any(domain in link_url for domain in suspicious_domains):
                indicators['suspicious_links'].append(link)
            
            # Check for misleading link text
            if any(keyword in link_text for keyword in ['click here', 'verify now', 'update account', 'confirm identity']):
                indicators['suspicious_links'].append(link)
        
        # Count urgency indicators
        urgency_keywords = ['urgent', 'immediate', 'expire', 'suspend', 'limited time', 'act now']
        indicators['urgency_indicators'] = sum(1 for keyword in urgency_keywords if keyword in content)
        
        # Count trust indicators (legitimate elements)
        trust_keywords = ['privacy policy', 'terms of service', 'contact us', 'about us']
        indicators['trust_indicators'] = sum(1 for keyword in trust_keywords if keyword in content)
        
        # Calculate basic risk score
        risk_score = 0.0
        risk_score += len(indicators['suspicious_forms']) * 2.0
        risk_score += len(indicators['suspicious_links']) * 1.0
        risk_score += indicators['urgency_indicators'] * 0.5
        risk_score -= indicators['trust_indicators'] * 0.3
        
        indicators['risk_score'] = max(0.0, min(10.0, risk_score))
        
        return indicators
