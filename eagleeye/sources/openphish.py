"""
OpenPhish API integration for EagleEye CLI
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
from .base import ScamSource, ScamSourceError
from ..database import ScamRecord


class OpenPhishSource(ScamSource):
    """OpenPhish API source for phishing URLs"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("openphish", api_key)
        self.base_url = "https://openphish.com/feed.txt"
        self.premium_url = "https://premium.openphish.com/feeds/premium.json"
        self.rate_limit_delay = 0.5  # OpenPhish is more lenient
    
    def is_configured(self) -> bool:
        """OpenPhish works without API key for basic feed"""
        return True  # API key is optional for basic feed
    
    async def fetch_recent_scams(self, limit: int = 50) -> List[ScamRecord]:
        """Fetch recent phishing URLs from OpenPhish"""
        try:
            # Use premium feed if API key available, otherwise basic feed
            if self.api_key:
                data = await self._fetch_premium_feed(limit)
            else:
                data = await self._fetch_basic_feed(limit)
            
            return data[:limit]
            
        except Exception as e:
            raise ScamSourceError(f"OpenPhish API error: {str(e)}")
    
    async def _fetch_basic_feed(self, limit: int) -> List[ScamRecord]:
        """Fetch from basic text feed"""
        try:
            response = await self._make_request(self.base_url, is_json=False)
            
            if not response:
                return []
            
            # Parse text feed - one URL per line
            urls = response.strip().split('\n')
            scams = []
            
            for i, url in enumerate(urls[:limit]):
                if url.strip():
                    scam = ScamRecord(
                        source="openphish",
                        source_id=f"openphish_{i}",
                        scam_type="phishing",
                        title=f"Phishing URL: {self._extract_domain(url)}",
                        description=f"Malicious URL detected: {url}",
                        url=url.strip(),
                        severity=7.5,  # Default severity for OpenPhish URLs
                        location="Unknown",
                        first_seen=datetime.utcnow(),
                        verified=True
                    )
                    scams.append(scam)
            
            return scams
            
        except Exception as e:
            raise ScamSourceError(f"Error fetching OpenPhish basic feed: {str(e)}")
    
    async def _fetch_premium_feed(self, limit: int) -> List[ScamRecord]:
        """Fetch from premium JSON feed (requires API key)"""
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            data = await self._make_request(
                self.premium_url, 
                headers=headers
            )
            
            if not isinstance(data, list):
                return []
            
            scams = []
            for item in data[:limit]:
                scam = self._parse_premium_item(item)
                if scam:
                    scams.append(scam)
            
            return scams
            
        except Exception as e:
            # Fall back to basic feed if premium fails
            return await self._fetch_basic_feed(limit)
    
    def _parse_premium_item(self, item: Dict[str, Any]) -> Optional[ScamRecord]:
        """Parse premium feed item to ScamRecord"""
        try:
            url = item.get('url', '')
            if not url:
                return None
            
            return ScamRecord(
                source="openphish",
                source_id=item.get('id', f"openphish_{hash(url)}"),
                scam_type="phishing",
                title=f"Phishing: {item.get('brand', self._extract_domain(url))}",
                description=item.get('description', f"Phishing URL: {url}"),
                url=url,
                severity=item.get('severity', 8.0),
                location=item.get('country', 'Unknown'),
                first_seen=self._parse_timestamp(item.get('discovered')),
                verified=item.get('verified', True)
            )
            
        except Exception:
            return None
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc or url
        except Exception:
            return url
    
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> datetime:
        """Parse timestamp string to datetime"""
        if not timestamp_str:
            return datetime.utcnow()
        
        try:
            # Try common timestamp formats
            formats = [
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d"
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            
            # If all formats fail, return current time
            return datetime.utcnow()
            
        except Exception:
            return datetime.utcnow()
    
    async def search_scams(
        self, 
        query: str, 
        scam_type: Optional[str] = None,
        limit: int = 50
    ) -> List[ScamRecord]:
        """Search OpenPhish for specific URLs or domains"""
        try:
            # For OpenPhish, we'll fetch recent data and filter locally
            all_scams = await self.fetch_recent_scams(limit * 2)
            
            # Filter by query (URL or domain matching)
            filtered_scams = []
            query_lower = query.lower()
            
            for scam in all_scams:
                if (query_lower in scam.url.lower() or 
                    query_lower in scam.title.lower() or
                    query_lower in scam.description.lower()):
                    
                    # Apply scam type filter if specified
                    if scam_type and scam_type.lower() != scam.scam_type.lower():
                        continue
                    
                    filtered_scams.append(scam)
                    
                    if len(filtered_scams) >= limit:
                        break
            
            return filtered_scams
            
        except Exception as e:
            raise ScamSourceError(f"OpenPhish search error: {str(e)}")
