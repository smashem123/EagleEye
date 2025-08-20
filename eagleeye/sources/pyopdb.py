"""
PyOpenPhishDB - Local OpenPhish database module for offline feeds
Provides hourly updated local database with hybrid AI detection
"""
import asyncio
import json
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import httpx
import hashlib

from .base import ScamSource, ScamSourceError
from ..database import ScamRecord


class PyOpenPhishDB(ScamSource):
    """Local OpenPhish database with offline feeds and AI hybrid detection"""
    
    def __init__(self, api_key: Optional[str] = None, db_path: Optional[Path] = None):
        super().__init__("pyopdb", api_key)
        self.db_path = db_path or Path.home() / ".eagleeye" / "pyopdb.db"
        self.feed_url = "https://openphish.com/feed.txt"
        self.premium_feed_url = "https://openphish.com/premium_feed.json"
        self.last_update_file = self.db_path.parent / "last_update.txt"
        self.update_interval = 3600  # 1 hour in seconds
        self.rate_limit_delay = 0.1  # Very fast for local DB
        
        # AI detection patterns for unknown scams
        self.ai_patterns = {
            'suspicious_domains': [
                r'[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}',  # IP-like domains
                r'[a-z]{20,}\.com',  # Very long random domains
                r'[0-9]{8,}\.com',   # Numeric domains
                r'[a-z]+-[a-z]+-[a-z]+\.(com|net|org)',  # Triple hyphen patterns
            ],
            'suspicious_paths': [
                r'/[a-z]{32,}/',     # Long random paths
                r'/login[0-9]+/',    # Numbered login pages
                r'/secure[0-9]+/',   # Numbered secure pages
                r'/verify[a-z0-9]+/', # Verification pages
            ],
            'phishing_keywords': [
                'verify', 'suspend', 'limited', 'confirm', 'update',
                'secure', 'account', 'billing', 'payment', 'urgent'
            ]
        }
        
        self._init_local_db()
    
    def _init_local_db(self) -> None:
        """Initialize local SQLite database"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS phish_urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    domain TEXT NOT NULL,
                    path TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source TEXT DEFAULT 'openphish',
                    confidence REAL DEFAULT 1.0,
                    location TEXT,
                    ai_detected BOOLEAN DEFAULT 0,
                    url_hash TEXT UNIQUE
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_domain ON phish_urls(domain)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_url_hash ON phish_urls(url_hash)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_first_seen ON phish_urls(first_seen)
            """)
    
    def _get_url_hash(self, url: str) -> str:
        """Generate hash for URL deduplication"""
        return hashlib.sha256(url.encode()).hexdigest()[:16]
    
    def _should_update(self) -> bool:
        """Check if database needs updating"""
        if not self.last_update_file.exists():
            return True
        
        try:
            with open(self.last_update_file, 'r') as f:
                last_update = float(f.read().strip())
            return time.time() - last_update > self.update_interval
        except (FileNotFoundError, ValueError):
            return True
    
    def _mark_updated(self) -> None:
        """Mark database as updated"""
        with open(self.last_update_file, 'w') as f:
            f.write(str(time.time()))
    
    async def _update_local_db(self) -> int:
        """Update local database from OpenPhish feeds"""
        if not self._should_update():
            return 0
        
        updated_count = 0
        
        try:
            # Try premium feed first if API key available
            if self.api_key:
                updated_count += await self._fetch_premium_feed()
            else:
                updated_count += await self._fetch_basic_feed()
            
            self._mark_updated()
            return updated_count
            
        except Exception as e:
            raise ScamSourceError(f"Failed to update PyOpenPhishDB: {e}")
    
    async def _fetch_basic_feed(self) -> int:
        """Fetch from basic text feed"""
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(self.feed_url, headers=self.headers)
            response.raise_for_status()
            
            urls = [line.strip() for line in response.text.split('\n') if line.strip()]
            return await self._store_urls(urls, source='openphish_basic')
    
    async def _fetch_premium_feed(self) -> int:
        """Fetch from premium JSON feed"""
        headers = {**self.headers, 'Authorization': f'Bearer {self.api_key}'}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(self.premium_feed_url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            urls = [item['url'] for item in data if 'url' in item]
            return await self._store_urls(urls, source='openphish_premium')
    
    async def _store_urls(self, urls: List[str], source: str) -> int:
        """Store URLs in local database with AI analysis"""
        stored_count = 0
        
        with sqlite3.connect(self.db_path) as conn:
            for url in urls:
                try:
                    parsed = urlparse(url)
                    domain = parsed.netloc
                    path = parsed.path
                    url_hash = self._get_url_hash(url)
                    
                    # AI-based confidence scoring
                    confidence, ai_detected = self._analyze_url_with_ai(url, domain, path)
                    
                    # Estimate location from domain
                    location = self._estimate_location(domain)
                    
                    conn.execute("""
                        INSERT OR REPLACE INTO phish_urls 
                        (url, domain, path, source, confidence, location, ai_detected, url_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (url, domain, path, source, confidence, location, ai_detected, url_hash))
                    
                    stored_count += 1
                    
                except Exception as e:
                    # Skip malformed URLs
                    continue
        
        return stored_count
    
    def _analyze_url_with_ai(self, url: str, domain: str, path: str) -> tuple[float, bool]:
        """AI-based URL analysis for confidence scoring"""
        import re
        
        confidence = 1.0
        ai_detected = False
        
        # Check domain patterns
        for pattern in self.ai_patterns['suspicious_domains']:
            if re.search(pattern, domain, re.IGNORECASE):
                confidence += 0.2
                ai_detected = True
        
        # Check path patterns
        for pattern in self.ai_patterns['suspicious_paths']:
            if re.search(pattern, path, re.IGNORECASE):
                confidence += 0.1
                ai_detected = True
        
        # Check for phishing keywords
        url_lower = url.lower()
        keyword_count = sum(1 for keyword in self.ai_patterns['phishing_keywords'] 
                          if keyword in url_lower)
        
        if keyword_count >= 2:
            confidence += 0.3
            ai_detected = True
        elif keyword_count == 1:
            confidence += 0.1
            ai_detected = True
        
        # Cap confidence at reasonable maximum
        confidence = min(confidence, 10.0)
        
        return confidence, ai_detected
    
    def _estimate_location(self, domain: str) -> str:
        """Estimate location from domain TLD and patterns"""
        domain_lower = domain.lower()
        
        # Country-specific TLDs
        tld_map = {
            '.uk': 'United Kingdom', '.de': 'Germany', '.fr': 'France',
            '.ca': 'Canada', '.au': 'Australia', '.jp': 'Japan',
            '.cn': 'China', '.ru': 'Russia', '.br': 'Brazil',
            '.in': 'India', '.mx': 'Mexico', '.it': 'Italy'
        }
        
        for tld, country in tld_map.items():
            if domain_lower.endswith(tld):
                return country
        
        # Default for common TLDs
        if any(domain_lower.endswith(tld) for tld in ['.com', '.net', '.org']):
            return 'United States'
        
        return 'Unknown'
    
    async def fetch_recent_scams(self, limit: int = 50) -> List[ScamRecord]:
        """Fetch recent scams from local database"""
        # Update database if needed
        await self._update_local_db()
        
        records = []
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM phish_urls 
                ORDER BY first_seen DESC 
                LIMIT ?
            """, (limit,))
            
            for row in cursor.fetchall():
                record = ScamRecord(
                    title=f"Phishing Site: {row['domain']}",
                    description=f"Malicious URL detected at {row['url']}",
                    scam_type="phishing",
                    source=self.name,
                    source_id=str(row['id']),
                    url=row['url'],
                    location=row['location'],
                    severity=min(row['confidence'] * 2, 10.0),  # Scale confidence to severity
                    confidence=row['confidence'],
                    first_seen=datetime.fromisoformat(row['first_seen']),
                    is_verified=not row['ai_detected'],  # Known DB entries are verified
                    raw_data={
                        'domain': row['domain'],
                        'path': row['path'],
                        'ai_detected': bool(row['ai_detected']),
                        'source_feed': row['source']
                    }
                )
                records.append(record)
        
        return records
    
    async def search_scams(self, query: str, limit: int = 20) -> List[ScamRecord]:
        """Search local database for specific scams"""
        records = []
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM phish_urls 
                WHERE domain LIKE ? OR url LIKE ?
                ORDER BY confidence DESC, first_seen DESC
                LIMIT ?
            """, (f'%{query}%', f'%{query}%', limit))
            
            for row in cursor.fetchall():
                record = ScamRecord(
                    title=f"Phishing Site: {row['domain']}",
                    description=f"Malicious URL matching '{query}'",
                    scam_type="phishing",
                    source=self.name,
                    source_id=str(row['id']),
                    url=row['url'],
                    location=row['location'],
                    severity=min(row['confidence'] * 2, 10.0),
                    confidence=row['confidence'],
                    first_seen=datetime.fromisoformat(row['first_seen']),
                    is_verified=not row['ai_detected'],
                    raw_data={
                        'domain': row['domain'],
                        'path': row['path'],
                        'ai_detected': bool(row['ai_detected']),
                        'source_feed': row['source']
                    }
                )
                records.append(record)
        
        return records
    
    def get_stats(self) -> Dict[str, Any]:
        """Get local database statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM phish_urls")
            total_urls = cursor.fetchone()[0]
            
            cursor = conn.execute("SELECT COUNT(*) FROM phish_urls WHERE ai_detected = 1")
            ai_detected = cursor.fetchone()[0]
            
            cursor = conn.execute("""
                SELECT COUNT(*) FROM phish_urls 
                WHERE first_seen >= datetime('now', '-24 hours')
            """)
            recent_24h = cursor.fetchone()[0]
            
            return {
                'total_urls': total_urls,
                'ai_detected': ai_detected,
                'known_database': total_urls - ai_detected,
                'recent_24h': recent_24h,
                'last_update': self.last_update_file.read_text() if self.last_update_file.exists() else 'Never'
            }
    
    def is_configured(self) -> bool:
        """Check if the source is properly configured"""
        return True  # Local DB doesn't require configuration
    
    def get_rate_limit_delay(self) -> float:
        """Get rate limit delay (very fast for local DB)"""
        return self.rate_limit_delay
