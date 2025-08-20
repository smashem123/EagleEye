"""
URLVoid API integration for EagleEye CLI
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
from .base import ScamSource, ScamSourceError
from ..database import ScamRecord


class URLVoidSource(ScamSource):
    """URLVoid API source for website reputation checking"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__("urlvoid", api_key)
        self.base_url = "https://api.urlvoid.com/v1"
        self.rate_limit_delay = 2.0  # URLVoid has strict rate limits
    
    def is_configured(self) -> bool:
        """URLVoid requires an API key"""
        return self.api_key is not None
    
    async def fetch_recent_scams(self, limit: int = 50) -> List[ScamRecord]:
        """URLVoid doesn't have a feed endpoint, so we'll return empty for now"""
        # URLVoid is primarily for checking specific URLs rather than providing feeds
        # In a real implementation, you might maintain a list of suspicious domains to check
        return []
    
    async def search_scams(self, query: str, limit: int = 50) -> List[ScamRecord]:
        """Check a specific URL/domain with URLVoid"""
        if not self.is_configured():
            raise ScamSourceError("URLVoid API key not configured")
        
        try:
            # Clean the query to extract domain
            domain = self._extract_domain(query)
            if not domain:
                return []
            
            # Make API request
            url = f"{self.base_url}/host/{domain}"
            data = await self._make_request(url)
            
            scams = []
            if self._is_suspicious(data):
                scam = self._parse_urlvoid_record(domain, data)
                if scam:
                    scams.append(scam)
            
            return scams
            
        except Exception as e:
            raise ScamSourceError(f"Failed to check URLVoid: {str(e)}")
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for URLVoid"""
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        return {}
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL or return as-is if already a domain"""
        url = url.strip().lower()
        
        # Remove protocol
        if url.startswith('http://'):
            url = url[7:]
        elif url.startswith('https://'):
            url = url[8:]
        
        # Remove path and query parameters
        if '/' in url:
            url = url.split('/')[0]
        if '?' in url:
            url = url.split('?')[0]
        
        # Basic domain validation
        if '.' not in url or len(url) < 4:
            return None
        
        return url
    
    def _is_suspicious(self, data: Dict[str, Any]) -> bool:
        """Determine if URLVoid response indicates suspicious activity"""
        # Check various indicators from URLVoid response
        detections = data.get('detections', 0)
        if isinstance(detections, int) and detections > 0:
            return True
        
        # Check for specific flags
        suspicious_flags = [
            'malware', 'phishing', 'suspicious', 'blacklisted',
            'malicious', 'fraud', 'scam'
        ]
        
        response_text = str(data).lower()
        for flag in suspicious_flags:
            if flag in response_text:
                return True
        
        return False
    
    def _parse_urlvoid_record(self, domain: str, data: Dict[str, Any]) -> Optional[ScamRecord]:
        """Parse URLVoid response into ScamRecord format"""
        try:
            detections = data.get('detections', 0)
            engines = data.get('engines', {})
            
            # Calculate severity based on detection count
            severity = min(10.0, 5.0 + (detections * 0.5))
            
            # Build description
            description = f"Domain flagged by {detections} security engines"
            if engines:
                engine_names = list(engines.keys())[:3]  # Show first 3 engines
                description += f" including {', '.join(engine_names)}"
            
            return ScamRecord(
                title=f"Suspicious Domain: {domain}",
                description=description,
                scam_type="suspicious",
                source="urlvoid",
                source_id=domain,
                url=f"http://{domain}",
                severity=severity,
                confidence=min(0.95, 0.5 + (detections * 0.1)),
                first_seen=datetime.utcnow(),
                is_verified=detections >= 3,  # Consider verified if 3+ engines detect
                tags=["domain", "suspicious", "urlvoid"],
                raw_data=data
            )
            
        except Exception as e:
            print(f"Warning: Failed to parse URLVoid record: {e}")
            return None
