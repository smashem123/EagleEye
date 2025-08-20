"""
Link scanning module for phishing and malware detection
Advanced URL analysis, reputation checking, and threat detection
"""
import asyncio
import re
import hashlib
import urllib.parse
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import httpx


class URLThreatType(Enum):
    """Types of URL threats"""
    PHISHING = "phishing"
    MALWARE = "malware"
    SCAM = "scam"
    SPAM = "spam"
    SUSPICIOUS = "suspicious"
    SAFE = "safe"
    UNKNOWN = "unknown"


class URLRiskLevel(Enum):
    """Risk levels for URLs"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LinkScanResult:
    """Result of URL scanning and analysis"""
    url: str
    normalized_url: str
    domain: str
    subdomain: Optional[str]
    path: str
    threat_type: URLThreatType
    risk_level: URLRiskLevel
    risk_score: float
    reputation_score: float
    is_malicious: bool
    is_phishing: bool
    is_suspicious: bool
    blacklist_matches: List[str]
    whitelist_matches: List[str]
    redirect_chain: List[str]
    final_url: Optional[str]
    ssl_valid: bool
    response_code: Optional[int]
    content_type: Optional[str]
    page_title: Optional[str]
    suspicious_patterns: List[str]
    domain_age_days: Optional[int]
    registrar: Optional[str]
    analysis_timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            'url': self.url,
            'normalized_url': self.normalized_url,
            'domain': self.domain,
            'subdomain': self.subdomain,
            'path': self.path,
            'threat_type': self.threat_type.value,
            'risk_level': self.risk_level.value,
            'risk_score': self.risk_score,
            'reputation_score': self.reputation_score,
            'is_malicious': self.is_malicious,
            'is_phishing': self.is_phishing,
            'is_suspicious': self.is_suspicious,
            'blacklist_matches': self.blacklist_matches,
            'whitelist_matches': self.whitelist_matches,
            'redirect_chain': self.redirect_chain,
            'final_url': self.final_url,
            'ssl_valid': self.ssl_valid,
            'response_code': self.response_code,
            'content_type': self.content_type,
            'page_title': self.page_title,
            'suspicious_patterns': self.suspicious_patterns,
            'domain_age_days': self.domain_age_days,
            'registrar': self.registrar,
            'analysis_timestamp': self.analysis_timestamp.isoformat()
        }


class LinkScanner:
    """Advanced URL scanner for threat detection"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.timeout = 10.0
        self.max_redirects = 10
        
        # Known malicious domain patterns
        self.malicious_patterns = [
            r'.*\.tk$', r'.*\.ml$', r'.*\.ga$', r'.*\.cf$',  # Free suspicious TLDs
            r'.*-paypal-.*', r'.*paypal-.*', r'.*-amazon-.*',  # Phishing patterns
            r'.*microsoft-.*', r'.*apple-.*', r'.*google-.*',
            r'.*-bank-.*', r'.*secure-.*', r'.*verify-.*',
            r'.*update-.*', r'.*suspended-.*', r'.*locked-.*'
        ]
        
        # Suspicious URL patterns
        self.suspicious_patterns = [
            r'.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*',  # IP addresses
            r'.*[0-9]{10,}.*',  # Long sequences of numbers
            r'.*[a-z]{20,}.*',  # Very long random strings
            r'.*bit\.ly.*', r'.*tinyurl.*', r'.*t\.co.*',  # URL shorteners
            r'.*\.zip$', r'.*\.exe$', r'.*\.scr$'  # Executable files
        ]
        
        # Phishing keywords
        self.phishing_keywords = [
            'verify', 'suspend', 'urgent', 'security', 'update',
            'confirm', 'validate', 'expire', 'lock', 'account',
            'login', 'signin', 'secure', 'alert', 'warning'
        ]
        
        # Legitimate domains whitelist
        self.trusted_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'ebay.com', 'facebook.com', 'twitter.com',
            'linkedin.com', 'github.com', 'stackoverflow.com'
        }
        
        # Known malicious domains (simplified - in production use threat feeds)
        self.blacklisted_domains = {
            'malicious-site.com', 'phishing-example.net', 'scam-site.org'
        }
    
    async def scan_url(self, url: str, deep_scan: bool = False) -> LinkScanResult:
        """Scan a URL for threats and malicious content"""
        
        # Normalize URL
        normalized_url = self._normalize_url(url)
        parsed_url = urllib.parse.urlparse(normalized_url)
        domain = parsed_url.netloc.lower()
        subdomain = self._extract_subdomain(domain)
        path = parsed_url.path
        
        # Check blacklists and whitelists
        blacklist_matches = self._check_blacklists(normalized_url, domain)
        whitelist_matches = self._check_whitelists(domain)
        
        # Follow redirects if deep scan enabled
        redirect_chain = []
        final_url = normalized_url
        ssl_valid = False
        response_code = None
        content_type = None
        page_title = None
        
        if deep_scan:
            redirect_data = await self._follow_redirects(normalized_url)
            redirect_chain = redirect_data.get('chain', [])
            final_url = redirect_data.get('final_url', normalized_url)
            ssl_valid = redirect_data.get('ssl_valid', False)
            response_code = redirect_data.get('response_code')
            content_type = redirect_data.get('content_type')
            page_title = redirect_data.get('page_title')
        
        # Detect suspicious patterns
        suspicious_patterns = self._detect_suspicious_patterns(normalized_url, domain, path)
        
        # Get domain information
        domain_age_days, registrar = await self._get_domain_info(domain)
        
        # Calculate reputation score
        reputation_score = self._calculate_reputation_score(
            domain, blacklist_matches, whitelist_matches, domain_age_days
        )
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(
            normalized_url, domain, suspicious_patterns, reputation_score,
            ssl_valid, response_code, len(redirect_chain)
        )
        
        # Determine threat type and risk level
        threat_type = self._determine_threat_type(
            normalized_url, domain, suspicious_patterns, blacklist_matches
        )
        risk_level = self._determine_risk_level(risk_score, threat_type)
        
        # Set boolean flags
        is_malicious = risk_score > 7.0 or len(blacklist_matches) > 0
        is_phishing = threat_type == URLThreatType.PHISHING
        is_suspicious = risk_score > 5.0 or len(suspicious_patterns) > 2
        
        return LinkScanResult(
            url=url,
            normalized_url=normalized_url,
            domain=domain,
            subdomain=subdomain,
            path=path,
            threat_type=threat_type,
            risk_level=risk_level,
            risk_score=risk_score,
            reputation_score=reputation_score,
            is_malicious=is_malicious,
            is_phishing=is_phishing,
            is_suspicious=is_suspicious,
            blacklist_matches=blacklist_matches,
            whitelist_matches=whitelist_matches,
            redirect_chain=redirect_chain,
            final_url=final_url,
            ssl_valid=ssl_valid,
            response_code=response_code,
            content_type=content_type,
            page_title=page_title,
            suspicious_patterns=suspicious_patterns,
            domain_age_days=domain_age_days,
            registrar=registrar,
            analysis_timestamp=datetime.now()
        )
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL to standard format"""
        url = url.strip()
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Parse and rebuild to normalize
        parsed = urllib.parse.urlparse(url)
        normalized = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        
        return normalized
    
    def _extract_subdomain(self, domain: str) -> Optional[str]:
        """Extract subdomain from domain"""
        parts = domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[:-2])
        return None
    
    def _check_blacklists(self, url: str, domain: str) -> List[str]:
        """Check URL against known blacklists"""
        matches = []
        
        # Check domain blacklist
        if domain in self.blacklisted_domains:
            matches.append(f"blacklisted_domain:{domain}")
        
        # Check malicious patterns
        for pattern in self.malicious_patterns:
            if re.match(pattern, domain):
                matches.append(f"malicious_pattern:{pattern}")
        
        # Check for IP addresses (often suspicious)
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            matches.append("ip_address_domain")
        
        return matches
    
    def _check_whitelists(self, domain: str) -> List[str]:
        """Check domain against trusted whitelist"""
        matches = []
        
        # Check exact domain match
        if domain in self.trusted_domains:
            matches.append(f"trusted_domain:{domain}")
        
        # Check if it's a subdomain of trusted domain
        for trusted in self.trusted_domains:
            if domain.endswith('.' + trusted):
                matches.append(f"trusted_subdomain:{trusted}")
        
        return matches
    
    async def _follow_redirects(self, url: str) -> Dict[str, Any]:
        """Follow redirect chain and analyze final destination"""
        redirect_data = {
            'chain': [],
            'final_url': url,
            'ssl_valid': False,
            'response_code': None,
            'content_type': None,
            'page_title': None
        }
        
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=self.max_redirects
            ) as client:
                response = await client.get(url)
                
                # Build redirect chain
                for resp in response.history:
                    redirect_data['chain'].append(str(resp.url))
                
                redirect_data['final_url'] = str(response.url)
                redirect_data['response_code'] = response.status_code
                redirect_data['content_type'] = response.headers.get('content-type', '')
                
                # Check SSL
                redirect_data['ssl_valid'] = str(response.url).startswith('https://')
                
                # Extract page title if HTML
                if 'text/html' in redirect_data['content_type']:
                    content = response.text[:5000]  # First 5KB only
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                    if title_match:
                        redirect_data['page_title'] = title_match.group(1).strip()
                
        except Exception:
            # If request fails, that's suspicious but not necessarily malicious
            pass
        
        return redirect_data
    
    def _detect_suspicious_patterns(self, url: str, domain: str, path: str) -> List[str]:
        """Detect suspicious patterns in URL"""
        patterns_found = []
        
        # Check URL against suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url):
                patterns_found.append(f"suspicious_url:{pattern}")
        
        # Check for phishing keywords
        for keyword in self.phishing_keywords:
            if keyword in url.lower():
                patterns_found.append(f"phishing_keyword:{keyword}")
        
        # Check for excessive subdomains (often used in phishing)
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            patterns_found.append(f"excessive_subdomains:{subdomain_count}")
        
        # Check for suspicious path patterns
        if re.search(r'/[a-f0-9]{32,}/', path):  # Long hex strings
            patterns_found.append("suspicious_path_hash")
        
        if path.count('/') > 5:  # Very deep paths
            patterns_found.append("deep_path_structure")
        
        # Check for homograph attacks (simplified)
        if any(ord(char) > 127 for char in domain):
            patterns_found.append("unicode_domain")
        
        return patterns_found
    
    async def _get_domain_info(self, domain: str) -> Tuple[Optional[int], Optional[str]]:
        """Get domain registration information (mock implementation)"""
        # In production, use WHOIS API or domain intelligence services
        
        # Mock data based on domain patterns
        if domain in self.trusted_domains:
            return 3650, "Trusted Registrar"  # 10+ years old
        elif any(pattern.replace('.*', '').replace('$', '') in domain for pattern in self.malicious_patterns):
            return 30, "Suspicious Registrar"  # Very new domain
        else:
            return 365, "Standard Registrar"  # 1 year old
    
    def _calculate_reputation_score(self, 
                                   domain: str, 
                                   blacklist_matches: List[str],
                                   whitelist_matches: List[str],
                                   domain_age_days: Optional[int]) -> float:
        """Calculate domain reputation score (0-10, higher is better)"""
        score = 5.0  # Neutral starting point
        
        # Whitelist boosts reputation significantly
        if whitelist_matches:
            score += 4.0
        
        # Blacklist severely hurts reputation
        score -= len(blacklist_matches) * 3.0
        
        # Domain age factor
        if domain_age_days:
            if domain_age_days > 1095:  # 3+ years
                score += 2.0
            elif domain_age_days > 365:  # 1+ years
                score += 1.0
            elif domain_age_days < 30:  # Very new
                score -= 2.0
        
        # Domain length and structure
        if len(domain) < 5:  # Very short domains are suspicious
            score -= 1.0
        elif len(domain) > 50:  # Very long domains are suspicious
            score -= 1.0
        
        return max(0.0, min(10.0, score))
    
    def _calculate_risk_score(self, 
                             url: str,
                             domain: str,
                             suspicious_patterns: List[str],
                             reputation_score: float,
                             ssl_valid: bool,
                             response_code: Optional[int],
                             redirect_count: int) -> float:
        """Calculate overall URL risk score (0-10, higher is riskier)"""
        risk_score = 0.0
        
        # Base risk from reputation (inverted)
        risk_score += (10.0 - reputation_score) * 0.7
        
        # Suspicious patterns increase risk
        risk_score += len(suspicious_patterns) * 0.5
        
        # SSL factor
        if not ssl_valid and 'login' in url.lower():
            risk_score += 2.0  # No SSL on login pages is very risky
        elif not ssl_valid:
            risk_score += 1.0
        
        # Response code factor
        if response_code:
            if response_code >= 400:  # Client/server errors
                risk_score += 1.0
            elif response_code in [301, 302] and redirect_count == 0:
                risk_score += 0.5  # Redirect without following is suspicious
        
        # Excessive redirects
        if redirect_count > 3:
            risk_score += min(redirect_count * 0.5, 2.0)
        
        # URL length factor
        if len(url) > 100:
            risk_score += 1.0
        
        return min(10.0, risk_score)
    
    def _determine_threat_type(self, 
                              url: str,
                              domain: str,
                              suspicious_patterns: List[str],
                              blacklist_matches: List[str]) -> URLThreatType:
        """Determine the primary threat type"""
        
        # Check for phishing indicators
        phishing_indicators = ['phishing_keyword', 'malicious_pattern', 'suspicious_url']
        if any(any(indicator in pattern for indicator in phishing_indicators) for pattern in suspicious_patterns):
            return URLThreatType.PHISHING
        
        # Check for malware indicators
        malware_indicators = ['.exe', '.zip', '.scr', 'download']
        if any(indicator in url.lower() for indicator in malware_indicators):
            return URLThreatType.MALWARE
        
        # Check blacklist matches
        if blacklist_matches:
            if any('malicious' in match for match in blacklist_matches):
                return URLThreatType.MALWARE
            else:
                return URLThreatType.SCAM
        
        # Suspicious but not clearly categorized
        if len(suspicious_patterns) > 2:
            return URLThreatType.SUSPICIOUS
        
        # Default based on risk
        if len(suspicious_patterns) > 0:
            return URLThreatType.SUSPICIOUS
        else:
            return URLThreatType.SAFE
    
    def _determine_risk_level(self, risk_score: float, threat_type: URLThreatType) -> URLRiskLevel:
        """Determine risk level from score and threat type"""
        
        # Boost risk level for certain threat types
        if threat_type in [URLThreatType.MALWARE, URLThreatType.PHISHING]:
            if risk_score >= 6.0:
                return URLRiskLevel.CRITICAL
            elif risk_score >= 4.0:
                return URLRiskLevel.HIGH
            else:
                return URLRiskLevel.MEDIUM
        
        # Standard risk level calculation
        if risk_score >= 8.0:
            return URLRiskLevel.CRITICAL
        elif risk_score >= 6.0:
            return URLRiskLevel.HIGH
        elif risk_score >= 4.0:
            return URLRiskLevel.MEDIUM
        elif risk_score >= 2.0:
            return URLRiskLevel.LOW
        else:
            return URLRiskLevel.SAFE
    
    async def batch_scan(self, urls: List[str], deep_scan: bool = False) -> List[LinkScanResult]:
        """Scan multiple URLs in batch"""
        results = []
        
        for url in urls:
            result = await self.scan_url(url, deep_scan)
            results.append(result)
            
            # Small delay to avoid overwhelming target servers
            await asyncio.sleep(0.2)
        
        return results
    
    def get_url_hash(self, url: str) -> str:
        """Generate hash for URL deduplication"""
        normalized = self._normalize_url(url)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

import re
import asyncio
import sqlite3
import hashlib
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

import httpx
from bs4 import BeautifulSoup


@dataclass
class LinkScanResult:
    """Result of link scanning analysis."""
    url: str
    domain: str
    is_safe: bool
    risk_score: float = 0.0
    threat_types: List[str] = None
    reputation_score: float = 5.0  # 0-10 scale, 5 is neutral
    is_phishing: bool = False
    is_malware: bool = False
    is_suspicious: bool = False
    redirect_chain: List[str] = None
    final_url: str = None
    page_title: str = None
    ssl_valid: bool = True
    domain_age: Optional[int] = None
    sources: List[str] = None
    confidence: float = 0.0
    
    def __post_init__(self):
        if self.threat_types is None:
            self.threat_types = []
        if self.redirect_chain is None:
            self.redirect_chain = []
        if self.sources is None:
            self.sources = []


class URLValidator:
    """Validates and normalizes URLs."""
    
    def __init__(self):
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download',
            '.stream', '.science', '.racing', '.review', '.country',
            '.kim', '.cricket', '.party', '.work', '.link', '.date'
        }
        
        self.suspicious_keywords = {
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'instagram', 'twitter', 'linkedin', 'netflix', 'spotify',
            'banking', 'secure', 'verify', 'update', 'suspended', 'urgent',
            'confirm', 'account', 'login', 'signin', 'password', 'security'
        }
    
    def validate_url(self, url: str) -> Tuple[bool, str, str]:
        """
        Validate and normalize URL.
        
        Returns:
            Tuple of (is_valid, normalized_url, domain)
        """
        if not url:
            return False, "", ""
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                return False, url, ""
            
            domain = parsed.netloc.lower()
            # Remove www prefix for consistency
            if domain.startswith('www.'):
                domain = domain[4:]
            
            normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                normalized_url += f"?{parsed.query}"
            
            return True, normalized_url, domain
            
        except Exception:
            return False, url, ""
    
    def analyze_url_structure(self, url: str, domain: str) -> Dict[str, Any]:
        """Analyze URL structure for suspicious patterns."""
        analysis = {
            'suspicious_tld': False,
            'suspicious_keywords': [],
            'long_subdomain': False,
            'ip_address': False,
            'url_shortener': False,
            'suspicious_path': False,
            'homograph_attack': False
        }
        
        # Check TLD
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                analysis['suspicious_tld'] = True
                break
        
        # Check for suspicious keywords in domain
        domain_lower = domain.lower()
        for keyword in self.suspicious_keywords:
            if keyword in domain_lower and keyword != domain_lower:
                analysis['suspicious_keywords'].append(keyword)
        
        # Check for long subdomains (potential typosquatting)
        parts = domain.split('.')
        if len(parts) > 3:
            analysis['long_subdomain'] = True
        
        # Check if domain is IP address
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, domain):
            analysis['ip_address'] = True
        
        # Check for URL shorteners
        shorteners = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'short.link', 'tiny.cc', 'is.gd', 'buff.ly'
        }
        if domain in shorteners:
            analysis['url_shortener'] = True
        
        # Check for suspicious path patterns
        parsed = urllib.parse.urlparse(url)
        if parsed.path:
            path_lower = parsed.path.lower()
            suspicious_path_keywords = [
                'login', 'signin', 'verify', 'update', 'secure',
                'account', 'suspend', 'confirm', 'validate'
            ]
            for keyword in suspicious_path_keywords:
                if keyword in path_lower:
                    analysis['suspicious_path'] = True
                    break
        
        # Basic homograph attack detection
        suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'х', 'у']  # Cyrillic lookalikes
        for char in suspicious_chars:
            if char in domain:
                analysis['homograph_attack'] = True
                break
        
        return analysis


class ThreatDatabase:
    """Local threat database for caching scan results."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize threat database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    url_hash TEXT NOT NULL,
                    is_safe BOOLEAN,
                    risk_score REAL,
                    threat_types TEXT,
                    reputation_score REAL,
                    is_phishing BOOLEAN DEFAULT 0,
                    is_malware BOOLEAN DEFAULT 0,
                    first_seen TIMESTAMP,
                    last_checked TIMESTAMP,
                    check_count INTEGER DEFAULT 1,
                    source TEXT,
                    metadata TEXT
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_url_hash 
                ON threat_urls(url_hash)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_domain 
                ON threat_urls(domain)
            ''')
    
    def hash_url(self, url: str) -> str:
        """Create hash of URL for indexing."""
        return hashlib.sha256(url.encode()).hexdigest()[:16]
    
    def cache_result(self, result: LinkScanResult, source: str = "scanner") -> bool:
        """Cache scan result in database."""
        try:
            url_hash = self.hash_url(result.url)
            now = datetime.now()
            
            with sqlite3.connect(self.db_path) as conn:
                # Check if URL already exists
                existing = conn.execute(
                    'SELECT id FROM threat_urls WHERE url_hash = ?',
                    (url_hash,)
                ).fetchone()
                
                if existing:
                    # Update existing record
                    conn.execute('''
                        UPDATE threat_urls 
                        SET is_safe = ?, risk_score = ?, threat_types = ?,
                            reputation_score = ?, is_phishing = ?, is_malware = ?,
                            last_checked = ?, check_count = check_count + 1
                        WHERE url_hash = ?
                    ''', (result.is_safe, result.risk_score, 
                          ','.join(result.threat_types), result.reputation_score,
                          result.is_phishing, result.is_malware, now, url_hash))
                else:
                    # Insert new record
                    conn.execute('''
                        INSERT INTO threat_urls 
                        (url, domain, url_hash, is_safe, risk_score, threat_types,
                         reputation_score, is_phishing, is_malware, first_seen,
                         last_checked, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (result.url, result.domain, url_hash, result.is_safe,
                          result.risk_score, ','.join(result.threat_types),
                          result.reputation_score, result.is_phishing,
                          result.is_malware, now, now, source))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error caching result: {e}")
            return False
    
    def get_cached_result(self, url: str, max_age_hours: int = 24) -> Optional[Dict[str, Any]]:
        """Get cached scan result if available and fresh."""
        url_hash = self.hash_url(url)
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                result = conn.execute('''
                    SELECT * FROM threat_urls 
                    WHERE url_hash = ? AND last_checked >= ?
                    ORDER BY last_checked DESC
                    LIMIT 1
                ''', (url_hash, cutoff_time)).fetchone()
                
                if result:
                    return {
                        'url': result['url'],
                        'domain': result['domain'],
                        'is_safe': bool(result['is_safe']),
                        'risk_score': result['risk_score'],
                        'threat_types': result['threat_types'].split(',') if result['threat_types'] else [],
                        'reputation_score': result['reputation_score'],
                        'is_phishing': bool(result['is_phishing']),
                        'is_malware': bool(result['is_malware']),
                        'last_checked': result['last_checked'],
                        'source': result['source']
                    }
                
                return None
                
        except Exception as e:
            print(f"Error getting cached result: {e}")
            return None


class PhishingDetector:
    """Detects phishing attempts in URLs and web content."""
    
    def __init__(self):
        self.phishing_patterns = [
            # Common phishing URL patterns
            r'[a-z]+-[a-z]+\.(tk|ml|ga|cf)',  # Suspicious TLD combinations
            r'(paypal|amazon|microsoft|apple|google|facebook)-[a-z]+\.',
            r'[a-z]+(paypal|amazon|microsoft|apple|google|facebook)\.',
            r'(secure|verify|update|confirm)-[a-z]+\.',
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
        ]
        
        self.phishing_keywords = {
            'urgent', 'suspended', 'verify', 'confirm', 'update',
            'secure', 'account', 'login', 'signin', 'password',
            'expired', 'limited', 'restricted', 'unusual'
        }
    
    def detect_phishing_url(self, url: str, domain: str) -> Tuple[bool, float, List[str]]:
        """Detect phishing patterns in URL."""
        indicators = []
        risk_score = 0.0
        
        url_lower = url.lower()
        domain_lower = domain.lower()
        
        # Check URL patterns
        for pattern in self.phishing_patterns:
            if re.search(pattern, url_lower):
                indicators.append(f"suspicious_pattern_{pattern[:20]}")
                risk_score += 2.0
        
        # Check for keyword stuffing in domain
        keyword_count = sum(1 for keyword in self.phishing_keywords 
                           if keyword in domain_lower)
        if keyword_count > 0:
            indicators.append("keyword_stuffing")
            risk_score += keyword_count * 1.5
        
        # Check for brand impersonation
        major_brands = [
            'paypal', 'amazon', 'microsoft', 'apple', 'google',
            'facebook', 'instagram', 'twitter', 'netflix', 'spotify'
        ]
        
        for brand in major_brands:
            if brand in domain_lower and not domain_lower.endswith(f'{brand}.com'):
                indicators.append(f"brand_impersonation_{brand}")
                risk_score += 3.0
        
        is_phishing = risk_score >= 3.0
        return is_phishing, min(risk_score, 10.0), indicators
    
    async def analyze_page_content(self, url: str) -> Dict[str, Any]:
        """Analyze webpage content for phishing indicators."""
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(url)
                
                if response.status_code != 200:
                    return {'error': f'HTTP {response.status_code}'}
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                analysis = {
                    'title': soup.title.string if soup.title else None,
                    'has_login_form': bool(soup.find('form', {'action': re.compile(r'login|signin', re.I)})),
                    'password_fields': len(soup.find_all('input', {'type': 'password'})),
                    'suspicious_text': [],
                    'external_links': 0,
                    'ssl_certificate': url.startswith('https://'),
                    'final_url': str(response.url)
                }
                
                # Check for suspicious text content
                text_content = soup.get_text().lower()
                suspicious_phrases = [
                    'verify your account', 'account suspended', 'urgent action',
                    'click here immediately', 'limited time', 'expires today',
                    'confirm your identity', 'update payment', 'security alert'
                ]
                
                for phrase in suspicious_phrases:
                    if phrase in text_content:
                        analysis['suspicious_text'].append(phrase)
                
                # Count external links
                domain = urllib.parse.urlparse(url).netloc
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('http') and domain not in href:
                        analysis['external_links'] += 1
                
                return analysis
                
        except Exception as e:
            return {'error': str(e)}


class LinkScanner:
    """Main link scanning system."""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.db_path = config_dir / "threats.db"
        
        self.validator = URLValidator()
        self.threat_db = ThreatDatabase(self.db_path)
        self.phishing_detector = PhishingDetector()
    
    async def scan_link(self, url: str, deep_scan: bool = True) -> LinkScanResult:
        """
        Comprehensive link scanning.
        
        Args:
            url: URL to scan
            deep_scan: Whether to perform content analysis
            
        Returns:
            LinkScanResult with threat analysis
        """
        # Validate URL
        is_valid, normalized_url, domain = self.validator.validate_url(url)
        
        if not is_valid:
            return LinkScanResult(
                url=url,
                domain="",
                is_safe=False,
                risk_score=10.0,
                threat_types=["invalid_url"],
                confidence=0.9
            )
        
        # Check cache first
        cached = self.threat_db.get_cached_result(normalized_url)
        if cached and not deep_scan:
            return LinkScanResult(
                url=normalized_url,
                domain=domain,
                is_safe=cached['is_safe'],
                risk_score=cached['risk_score'],
                threat_types=cached['threat_types'],
                reputation_score=cached['reputation_score'],
                is_phishing=cached['is_phishing'],
                is_malware=cached['is_malware'],
                sources=['cache'],
                confidence=0.8
            )
        
        # Initialize result
        result = LinkScanResult(
            url=normalized_url,
            domain=domain,
            is_safe=True,
            confidence=0.7
        )
        
        # Analyze URL structure
        structure_analysis = self.validator.analyze_url_structure(normalized_url, domain)
        risk_score = 0.0
        
        # Calculate risk based on structure
        if structure_analysis['suspicious_tld']:
            risk_score += 2.0
            result.threat_types.append("suspicious_tld")
        
        if structure_analysis['suspicious_keywords']:
            risk_score += len(structure_analysis['suspicious_keywords']) * 1.5
            result.threat_types.append("suspicious_keywords")
        
        if structure_analysis['long_subdomain']:
            risk_score += 1.5
            result.threat_types.append("long_subdomain")
        
        if structure_analysis['ip_address']:
            risk_score += 3.0
            result.threat_types.append("ip_address")
        
        if structure_analysis['homograph_attack']:
            risk_score += 4.0
            result.threat_types.append("homograph_attack")
        
        # Phishing detection
        is_phishing, phishing_score, phishing_indicators = self.phishing_detector.detect_phishing_url(
            normalized_url, domain
        )
        
        if is_phishing:
            result.is_phishing = True
            risk_score += phishing_score
            result.threat_types.extend(phishing_indicators)
        
        # Deep content analysis if requested
        if deep_scan:
            try:
                content_analysis = await self.phishing_detector.analyze_page_content(normalized_url)
                
                if 'error' not in content_analysis:
                    result.page_title = content_analysis.get('title')
                    result.final_url = content_analysis.get('final_url', normalized_url)
                    result.ssl_valid = content_analysis.get('ssl_certificate', False)
                    
                    # Adjust risk based on content
                    if content_analysis.get('has_login_form') and result.is_phishing:
                        risk_score += 2.0
                        result.threat_types.append("phishing_login_form")
                    
                    if content_analysis.get('suspicious_text'):
                        risk_score += len(content_analysis['suspicious_text']) * 0.5
                        result.threat_types.append("suspicious_content")
                    
                    if not result.ssl_valid:
                        risk_score += 1.0
                        result.threat_types.append("no_ssl")
                    
                    result.sources.append('content_analysis')
                    result.confidence = min(0.95, result.confidence + 0.2)
                
            except Exception as e:
                print(f"Content analysis failed: {e}")
        
        # Finalize result
        result.risk_score = min(risk_score, 10.0)
        result.is_safe = risk_score < 3.0
        result.is_suspicious = 3.0 <= risk_score < 6.0
        result.reputation_score = max(0.0, 10.0 - risk_score)
        
        # Cache result
        self.threat_db.cache_result(result, "link_scanner")
        
        return result
    
    def report_malicious_link(self, url: str, threat_type: str = "phishing",
                             description: str = None) -> bool:
        """Report a malicious link."""
        is_valid, normalized_url, domain = self.validator.validate_url(url)
        
        if not is_valid:
            return False
        
        # Create high-risk result for reported link
        result = LinkScanResult(
            url=normalized_url,
            domain=domain,
            is_safe=False,
            risk_score=9.0,
            threat_types=[threat_type, "user_reported"],
            is_phishing=(threat_type == "phishing"),
            is_malware=(threat_type == "malware"),
            sources=["user_report"],
            confidence=0.9
        )
        
        return self.threat_db.cache_result(result, "user_report")
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat scanning statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Total URLs scanned
                total = conn.execute('SELECT COUNT(*) as count FROM threat_urls').fetchone()['count']
                
                # Threat breakdown
                threats = conn.execute('''
                    SELECT 
                        SUM(CASE WHEN is_safe = 0 THEN 1 ELSE 0 END) as malicious,
                        SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as phishing,
                        SUM(CASE WHEN is_malware = 1 THEN 1 ELSE 0 END) as malware,
                        SUM(CASE WHEN risk_score >= 6.0 THEN 1 ELSE 0 END) as high_risk
                    FROM threat_urls
                ''').fetchone()
                
                # Recent scans (last 24 hours)
                day_ago = datetime.now() - timedelta(days=1)
                recent = conn.execute(
                    'SELECT COUNT(*) as count FROM threat_urls WHERE last_checked >= ?',
                    (day_ago,)
                ).fetchone()['count']
                
                # Top threat types
                threat_types = conn.execute('''
                    SELECT threat_types, COUNT(*) as count
                    FROM threat_urls 
                    WHERE threat_types IS NOT NULL AND threat_types != ''
                    GROUP BY threat_types 
                    ORDER BY count DESC 
                    LIMIT 10
                ''').fetchall()
                
                return {
                    'total_urls_scanned': total,
                    'recent_scans': recent,
                    'malicious_urls': threats['malicious'] or 0,
                    'phishing_urls': threats['phishing'] or 0,
                    'malware_urls': threats['malware'] or 0,
                    'high_risk_urls': threats['high_risk'] or 0,
                    'top_threat_types': [
                        {
                            'types': row['threat_types'],
                            'count': row['count']
                        }
                        for row in threat_types
                    ]
                }
                
        except Exception as e:
            return {'error': str(e)}
