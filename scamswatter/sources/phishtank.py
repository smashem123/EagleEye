"""
PhishTank API integration for ScamSwatter CLI
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
from .base import ScamSource, ScamSourceError
from ..database import ScamRecord


class PhishTankSource(ScamSource):
    """PhishTank API source for phishing URLs"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("phishtank", api_key)
        self.base_url = "https://checkurl.phishtank.com/checkurl/"
        self.feed_url = "http://data.phishtank.com/data/online-valid.json"
        self.rate_limit_delay = 1.0  # PhishTank has rate limits
    
    def is_configured(self) -> bool:
        """PhishTank can work without API key for basic functionality"""
        return True  # API key is optional for some endpoints
    
    async def fetch_recent_scams(self, limit: int = 50) -> List[ScamRecord]:
        """Fetch recent phishing URLs from PhishTank"""
        try:
            # Use the public feed (no API key required)
            data = await self._make_request(self.feed_url)
            
            if not isinstance(data, list):
                raise ScamSourceError("Invalid response format from PhishTank")
            
            scams = []
            for item in data[:limit]:
                scam = self._parse_phishtank_record(item)
                if scam:
                    scams.append(scam)
            
            return scams
            
        except Exception as e:
            raise ScamSourceError(f"Failed to fetch from PhishTank: {str(e)}")
    
    async def search_scams(self, query: str, limit: int = 50) -> List[ScamRecord]:
        """Search PhishTank for specific URLs or domains"""
        # For search, we need to check individual URLs
        if not self.api_key:
            raise ScamSourceError("API key required for PhishTank URL checking")
        
        try:
            # Check if the query looks like a URL
            if not (query.startswith('http://') or query.startswith('https://')):
                query = f"http://{query}"
            
            params = {
                'url': query,
                'format': 'json'
            }
            
            data = await self._make_request(self.base_url, method="POST", data=params)
            
            scams = []
            if data.get('results') and data['results'].get('in_database'):
                # Convert single result to our format
                result = data['results']
                scam = ScamRecord(
                    title=f"Phishing URL: {query}",
                    description=f"URL flagged as phishing by PhishTank community",
                    scam_type="phishing",
                    source="phishtank",
                    source_id=str(result.get('phish_id', query)),
                    url=query,
                    severity=8.0 if result.get('verified') else 6.0,
                    confidence=0.9 if result.get('verified') else 0.7,
                    is_verified=bool(result.get('verified')),
                    first_seen=datetime.utcnow(),
                    raw_data=result
                )
                scams.append(scam)
            
            return scams
            
        except Exception as e:
            raise ScamSourceError(f"Failed to search PhishTank: {str(e)}")
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for PhishTank"""
        if self.api_key:
            return {"X-API-Key": self.api_key}
        return {}
    
    def _parse_phishtank_record(self, item: Dict[str, Any]) -> Optional[ScamRecord]:
        """Parse a PhishTank record into our ScamRecord format"""
        try:
            # Extract basic information
            phish_id = item.get('phish_id')
            url = item.get('url')
            
            if not phish_id or not url:
                return None
            
            # Parse submission time
            submission_time = item.get('submission_time')
            first_seen = None
            if submission_time:
                try:
                    first_seen = datetime.fromisoformat(submission_time.replace('T', ' ').replace('+00:00', ''))
                except:
                    first_seen = datetime.utcnow()
            else:
                first_seen = datetime.utcnow()
            
            # Determine verification status
            verified = item.get('verified') == 'yes'
            online = item.get('online') == 'yes'
            
            # Calculate severity
            severity = 8.0 if verified else 6.0
            if not online:
                severity -= 2.0
            
            # Extract target information
            target = item.get('target', '')
            title = f"Phishing: {target}" if target else f"Phishing URL"
            
            description = f"Phishing URL targeting {target}" if target else "Phishing URL detected by community"
            if not online:
                description += " (Currently offline)"
            
            return ScamRecord(
                title=title,
                description=description,
                scam_type="phishing",
                source="phishtank",
                source_id=str(phish_id),
                url=url,
                severity=max(0.0, min(10.0, severity)),
                confidence=0.9 if verified else 0.7,
                first_seen=first_seen,
                is_verified=verified,
                tags=["phishing", "url", target.lower()] if target else ["phishing", "url"],
                raw_data=item
            )
            
        except Exception as e:
            print(f"Warning: Failed to parse PhishTank record: {e}")
            return None
