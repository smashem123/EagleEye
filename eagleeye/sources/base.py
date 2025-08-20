"""
Base class for scam intelligence API sources
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
import httpx
from ..database import ScamRecord


class ScamSourceError(Exception):
    """Base exception for scam source errors"""
    pass


class ScamSource(ABC):
    """Abstract base class for scam intelligence sources"""
    
    def __init__(self, name: str, api_key: Optional[str] = None):
        self.name = name
        self.api_key = api_key
        self.rate_limit_delay = 1.0  # seconds between requests
        self.timeout = 30.0  # request timeout
        self.max_retries = 3
    
    @abstractmethod
    async def fetch_recent_scams(self, limit: int = 50) -> List[ScamRecord]:
        """Fetch recent scam records from the source"""
        pass
    
    @abstractmethod
    async def search_scams(self, query: str, limit: int = 50) -> List[ScamRecord]:
        """Search for scams matching a query"""
        pass
    
    @abstractmethod
    def is_configured(self) -> bool:
        """Check if the source is properly configured"""
        pass
    
    async def test_connection(self) -> bool:
        """Test if the API connection is working"""
        try:
            # Try to fetch a small number of records
            await self.fetch_recent_scams(limit=1)
            return True
        except Exception:
            return False
    
    async def _make_request(
        self, 
        url: str, 
        method: str = "GET", 
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make an HTTP request with retry logic"""
        
        if headers is None:
            headers = {}
        
        # Add API key to headers if available
        if self.api_key:
            headers.update(self._get_auth_headers())
        
        # Add user agent
        headers["User-Agent"] = "EagleEye CLI/1.0"
        
        for attempt in range(self.max_retries):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    if method.upper() == "GET":
                        response = await client.get(url, params=params, headers=headers)
                    elif method.upper() == "POST":
                        response = await client.post(url, params=params, headers=headers, json=data)
                    else:
                        raise ScamSourceError(f"Unsupported HTTP method: {method}")
                    
                    response.raise_for_status()
                    
                    # Rate limiting
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(self.rate_limit_delay)
                    
                    return response.json()
                    
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:  # Rate limited
                    wait_time = self.rate_limit_delay * (2 ** attempt)
                    await asyncio.sleep(wait_time)
                    continue
                elif e.response.status_code in [401, 403]:  # Auth errors
                    raise ScamSourceError(f"Authentication failed for {self.name}")
                else:
                    raise ScamSourceError(f"HTTP error {e.response.status_code} from {self.name}")
            
            except httpx.RequestError as e:
                if attempt == self.max_retries - 1:
                    raise ScamSourceError(f"Request failed for {self.name}: {str(e)}")
                await asyncio.sleep(self.rate_limit_delay * (2 ** attempt))
        
        raise ScamSourceError(f"Max retries exceeded for {self.name}")
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers (override in subclasses)"""
        return {}
    
    def _normalize_scam_type(self, raw_type: str) -> str:
        """Normalize scam type to standard categories"""
        raw_type = raw_type.lower().strip()
        
        # Mapping of common variations to standard types
        type_mapping = {
            'phish': 'phishing',
            'phishing': 'phishing',
            'malware': 'malware',
            'malicious': 'malware',
            'fraud': 'fraud',
            'scam': 'fraud',
            'spam': 'spam',
            'suspicious': 'suspicious',
            'fake': 'fake_website',
            'counterfeit': 'fake_website',
            'investment': 'investment_fraud',
            'romance': 'romance_scam',
            'tech support': 'tech_support',
            'lottery': 'lottery_scam',
            'advance fee': 'advance_fee_fraud',
        }
        
        for key, standard_type in type_mapping.items():
            if key in raw_type:
                return standard_type
        
        return 'unknown'
    
    def _calculate_severity(self, raw_data: Dict[str, Any]) -> float:
        """Calculate severity score based on raw data (0-10 scale)"""
        # Base severity
        severity = 5.0
        
        # Adjust based on source confidence
        if 'confidence' in raw_data:
            confidence = float(raw_data['confidence'])
            severity += (confidence - 0.5) * 4  # Scale confidence to severity
        
        # Adjust based on verification status
        if raw_data.get('verified', False):
            severity += 2.0
        
        # Adjust based on report count or popularity
        if 'report_count' in raw_data:
            count = int(raw_data['report_count'])
            if count > 100:
                severity += 2.0
            elif count > 10:
                severity += 1.0
        
        # Clamp to 0-10 range
        return max(0.0, min(10.0, severity))
    
    def _extract_urls(self, data: Dict[str, Any]) -> List[str]:
        """Extract URLs from raw data"""
        urls = []
        
        # Common URL fields
        url_fields = ['url', 'link', 'website', 'domain', 'target']
        
        for field in url_fields:
            if field in data and data[field]:
                urls.append(str(data[field]))
        
        return list(set(urls))  # Remove duplicates
    
    def _extract_location(self, data: Dict[str, Any]) -> Optional[str]:
        """Extract location information from raw data"""
        location_fields = ['country', 'location', 'region', 'geo']
        
        for field in location_fields:
            if field in data and data[field]:
                return str(data[field])
        
        return None
